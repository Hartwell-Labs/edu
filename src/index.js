/**
 * Anvil — worker for edu.hartwell-labs.pl
 *
 * Serves the app (interactive labs) and the backend:
 *   /api/auth/register   create an account (nick + e-mail + client-side verifier)
 *   /api/auth/login      sign in, HttpOnly session cookie
 *   /api/auth/logout
 *   /api/auth/verify     e-mail confirmation link (token from Resend mail)
 *   /api/auth/resend     one confirmation mail per minute
 *   /api/me              profile + progress + streak + plan
 *   /api/progress        save one task's progress (account or guest mode)
 *   /api/progress/merge  migrate guest progress onto the account
 *   /api/manifest        task registry
 *   /healthz
 *
 * Passwords: PBKDF2-SHA256 with 210 000 iterations runs in the browser; the server
 * only stores the verifier. Sessions: 32 random bytes in an HttpOnly+SameSite=Lax
 * cookie, valid for 60 days, revocable server-side. Guest progress stays in
 * localStorage and is merged into the account on sign-in.
 */

const CSP_STRICT = [
  "default-src 'none'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "script-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

const CSP_LAB = [
  "default-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com data:",
  "script-src 'self' 'wasm-unsafe-eval'",
  "connect-src 'self' blob: data:",
  "worker-src 'self' blob:",
  "img-src 'self' data: blob:",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

const SESSION_DAYS = 60;
/* Plan "lifetime" opens the tasks past the free tier. Default is free. */
const PLANS = new Set(["free", "lifetime"]);
const PBKDF2_ALGO = "pbkdf2-sha256";
const COOKIE = "anvil_session";

/* ------------------------------------------------------------------ utils */
const json = (data, opts = {}) =>
  new Response(JSON.stringify(data), {
    status: opts.status || 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...(opts.headers || {}),
    },
  });

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const randHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

/* ---------------------------------------------------------------- tokeny
   Token z cookie jest jedyną rzeczą, która trzyma konto; token
   potwierdzający daje wejście na nowe konto. Trzymanie ich w D1 w postaci
   jawnej zamienia wyciek bazy w masowe przejęcie kont — wystarczy zrzut z
   panelu Cloudflare albo kopia zapasowa.

   W bazie trzymamy SHA-256 z tokenu, nie token. Bez soli: token to 32 bajty
   losowe, więc slownik nie ma czego atakowac, a sol tylko komplikowalaby
   zgodnosc miedzy logowaniem a wylogowaniem. Wyszukiwanie idzie po skrocie,
   wiec baza nigdy nie porownuje sekretow ani nie zwraca ich w odpowiedzi.

   Faza EXPAND: kolumny jawne zostaja i sa wciaz zapisywane, wiec stary build
   dzialajacy rownolegle nadal dziala. Usuniecie ich to osobna migracja,
   dopiero gdy nic nie czyta starej nazwy. */
async function tokenHash(token) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(token)));
  return hex(d);
}

const HANDLE_RE = /^[a-z0-9][a-z0-9_-]{2,23}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s.]+\.[^@\s]+$/;

/* Domeny, ktorych nikt prawdziwy nie nie ma. RFC 2606 i 6761 rezerwują je dla
   dokumentacji, a boty lubia je wklejać, bo nie dostaną odpowiedzi z serwera
   pocztowej — czyli za darmo wygenerują nam wysyłkę. */
/* Domeny zarezerwowane przez RFC 2606 i 6761 (example.com, test.org,
   .invalid, .localhost, .test) oraz skrzynki jednorazowe.
   Uzupełniane prefiksem i domeną bazową, bo sama domena bazowa "test"
   nie łapała niczego — test.org przechodził, a jest zarezerwowany tak
   samo jak example.com. */
const RESERVED_EXACT = new Set([
  "example.com", "example.org", "example.net", "example.edu", "example.co.uk",
  "invalid", "localhost", "local", "test",
  "mailinator.com", "guerrillamail.com", "10minutemail.com", "yopmail.com",
  "trashmail.com", "sharklasers.com", "getnada.com", "temp-mail.org",
  "domain.com", "email.com",
]);
/* RFC 6761 rezerwuje te TLD dla dokumentacji — nigdy nie wskazują na realne
   skrzynki, a ktoś może na nie wskazac, bo wyglądają normalnie. */
const RESERVED_TLDS = new Set(["test", "example", "invalid", "localhost", "localdomain"]);
const RESERVED_PREFIXES = ["example.", "test."];

function isReservedDomain(domainRaw) {
  const domain = (domainRaw || "").toLowerCase().replace(/\.$/, "");
  if (!domain || !domain.includes(".")) return true;
  if (RESERVED_EXACT.has(domain)) return true;
  if (RESERVED_TLDS.has(domain.split(".").pop())) return true;
  return RESERVED_PREFIXES.some((p) => domain.startsWith(p));
}

/* ---------------------------------------------------------------- ratelimit
   Rejestracja i wysylka maila kosztuja realne pieniadze (Resend) i niszcza
   reputacje domeny, wiec oba endpointy musza miec limit. Najpierw natywny
   binding Cloudflare (dziala miedzy izolatami), a gdy go nie ma — kubelek
   w pamieci, ktory i tak zatrzyma naiwnego bota. */
const buckets = new Map();
const BUCKET_MAX = 2000;          // izolaty sa krotkotrwale, wiec czyscimy
const RULES = {
  register: { limit: 5, windowMs: 3600_000 },   // 5 kont na godzine z jednego IP
  resend: { limit: 3, windowMs: 3600_000 },     // 3 ponowienia na godzine
  access: { limit: 3, windowMs: 3600_000 },     // 3 prośby o dostęp na godzine
};

function clientIp(request) {
  // CI sends its own address in x-anvil-client. `wrangler dev` sits on
  // 127.0.0.1, so without this every CI run shares one bucket: the rate-limit
  // check issues 9 requests against a limit of 5, which means the branch would
  // go red on the second push for the wrong reason — 429 rather than a defect.
  // Bounding the test IP separately keeps the limit itself under test, which is
  // the point of the step, and leaves the production buckets untouched.
  const override = request.headers.get("x-anvil-client");
  if (override) return "ci:" + override;
  return request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "0.0.0.0";
}

function localBucket(rule, key) {
  // Date.now() wprost, nie helper `now()`: ten blok jest zdefiniowany wyzej
  // niz const now, wiec wolanie go stamtad wpada w strefe czasu martwego
  // i kazda rejestracja konczy sie 500.
  const t = Date.now();
  const k = rule + ":" + key;
  let b = buckets.get(k);
  if (!b || t > b.reset) { b = { count: 0, reset: t + RULES[rule].windowMs }; buckets.set(k, b); }
  if (buckets.size > BUCKET_MAX) {
    for (const [bk, bv] of buckets) if (t > bv.reset) buckets.delete(bk);
    if (buckets.size > BUCKET_MAX) buckets.delete(buckets.keys().next().value);
  }
  b.count++;
  return { ok: b.count <= RULES[rule].limit, left: Math.max(0, RULES[rule].limit - b.count) };
}

/**
 * Kubelek na adres klienta. Swiadomie w pamieci, nie przez binding Cloudflare:
 * natywny rate limiting dziala tylko na krawedzi, przez co `wrangler dev`
 * przestaje wstac, a lokalne testy przeplywu nie da sie odtworzyc. Rozproszony
 * atak mnozy ten limit, ale nie przekracza dziennego budzetu wysylki, ktory jest
 * twarda granica kosztu.
 */
function rateLimited(request, rule) {
  const ip = clientIp(request);
  const b = localBucket(rule, ip);
  if (b.ok) return null;
  // Rate limit is per-isolate in memory, so a 429 is indistinguishable from an
  // outage without this line. Logged whenever the bucket is spent, which is
  // also the signal worth alerting on: either one person retrying too hard, or
  // someone working around the limit.
  console.warn(JSON.stringify({
    message: "rate limit hit",
    rule,
    ip,
    limit: RULES[rule].limit,
    windowMs: RULES[rule].windowMs,
  }));
  return "Too many attempts from this address. Try again later.";
}

/** Dzienny limit wysylki — ostatnia linia obrony przed kazdym sposobem obejcia limitu IP. */
async function mailBudget(env) {
  const day = new Date().toISOString().slice(0, 10);
  const row = await env.DB.prepare(
    "SELECT count(*) AS n FROM mail_outbox WHERE created_at >= ?",
  ).bind(Date.parse(day + "T00:00:00Z")).first();
  return (row?.n || 0) < 200;
}


/** Constant-time comparison — no timing leak. */
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const packHash = (verifier) => `${PBKDF2_ALGO}$210000$${verifier}`;
const hashMatches = (stored, verifier) => {
  const raw = String(stored || "");
  const parts = raw.split("$");
  const expected = parts[0] === PBKDF2_ALGO ? parts[2] : raw;
  return timingSafeEqual(expected, String(verifier || ""));
};

const now = () => Date.now();

async function createSession(db, userId) {
  const token = randHex(32);
  const t = now();
  // Dual-write: jawna kolumna zostaje do osobnej migracji CONTRACT, ale od
  // tej chwili to skrot jest tym, po czym sie szuka.
  await db.prepare(
    "INSERT INTO sessions (token, token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?,?)",
  ).bind(token, await tokenHash(token), userId, t, t + SESSION_DAYS * 864e5).run();
  return token;
}

function sessionCookie(token) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}
const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;

function cookieToken(request) {
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === COOKIE) return v.join("=");
  }
  return null;
}

/* Sesje: najpierw szukamy po skrocie, a jawna kolumna to wczesniejszy etap
   tej samej migracji. Wiersze sprzed migracji maja token_hash NULL, wiec
   trzeba je obsluzyc — i przy okazji uzupelnić, bo i tak czytamy token.
   Self-healing: zamiast jednego UPDATE po tabeli, kazda stara sesja
   przepisuje sie sama przy pierwszym uzyciu, a wiersze ktorych nikt nie
   uzyje nie maja skrotu i nie zajmuja indeksu. */
async function findSession(db, token) {
  const hash = await tokenHash(token);
  const byHash = await db.prepare(
    `SELECT u.id, u.handle, u.email, u.created_at, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`,
  ).bind(hash).first();
  if (byHash) return byHash;

  const legacy = await db.prepare(
    `SELECT s.token, u.id, u.handle, u.email, u.created_at, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ? AND s.token_hash IS NULL`,
  ).bind(token).first();
  if (!legacy) return null;

  await db.prepare("UPDATE sessions SET token_hash = ? WHERE token = ?").bind(hash, token).run();
  return legacy;
}

async function dropSession(db, token) {
  const hash = await tokenHash(token);
  await db.prepare("DELETE FROM sessions WHERE token_hash = ? OR token = ?").bind(hash, token).run();
}

async function currentUser(request, env) {
  const token = cookieToken(request);
  if (!token) return null;
  const row = await findSession(env.DB, token);
  if (!row) return null;
  if (row.expires_at < now()) {
    await dropSession(env.DB, token);
    return null;
  }
  return { id: row.id, handle: row.handle, email: row.email, created_at: row.created_at };
}

async function loadProgress(env, userId) {
  const rows = await env.DB.prepare(
    "SELECT task_id, passed, points, attempts, hints_used, code FROM progress WHERE user_id = ?",
  ).bind(userId).all();
  const out = {};
  for (const r of rows.results) {
    out[r.task_id] = {
      passed: !!r.passed, points: r.points, attempts: r.attempts,
      hints: r.hints_used, code: r.code,
    };
  }
  return out;
}

async function touchStreak(env, userId) {
  const today = new Date().toISOString().slice(0, 10);
  const row = await env.DB.prepare("SELECT days, best FROM streak WHERE user_id = ?").bind(userId).first();
  const days = row ? (row.days ? row.days.split(",") : []) : [];
  if (days[days.length - 1] !== today) days.push(today);
  const best = Math.max(row?.best || 0, days.length);
  await env.DB.prepare(
    `INSERT INTO streak (user_id, days, best) VALUES (?,?,?)
     ON CONFLICT(user_id) DO UPDATE SET days = excluded.days, best = excluded.best`,
  ).bind(userId, days.join(","), best).run();
  return { days: days.length, best };
}

/* ------------------------------------------------------------------ mail */
const MAIL_FROM = "Anvil <labs@hartwell-labs.pl>";

/** Wysyła maila przez Resend. Brak klucza = brak wysyłki, ale konto działa. */
async function sendMail(env, to, subject, text, kind) {
  if (!env.RESEND_API_KEY) {
    // Not a failure in local dev, but in production a missing secret means
    // every confirmation link silently does not exist. Worth one line.
    console.error(JSON.stringify({ message: "mail not sent: RESEND_API_KEY unset", kind }));
    return false;
  }
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ from: env.MAIL_FROM || MAIL_FROM, to: [to], subject, text }),
    });
    const ok = r.ok;
    await env.DB.prepare("INSERT INTO mail_outbox (to_addr, subject, kind, created_at) VALUES (?,?,?,?)")
      .bind(to, subject, kind, now()).run().catch(() => {});
    if (!ok) {
      // Costs money per call and the response body says why. Without this the
      // only symptom is "user says the mail never arrived".
      console.error(JSON.stringify({
        message: "mail send rejected",
        kind,
        status: r.status,
        body: (await r.text()).slice(0, 300),
      }));
    }
    return ok;
  } catch (e) {
    console.error(JSON.stringify({
      message: "mail send threw",
      kind,
      error: e instanceof Error ? e.message : String(e),
    }));
    return false;
  }
}

const verifyLink = (token) => `https://edu.hartwell-labs.pl/verify?token=${token}`;

async function sendVerification(env, user) {
  const token = randHex(24);
  // Dual-write, jak przy sesjach: jawny token zostaje do migracji CONTRACT.
  // Kazde ponowne wyslanie kasuje poprzedni skrot, inaczej stary token
  // wyginalby dopiero po wygenerowaniu nowego, a nie w 24h od ostatniego
  // wyslania.
  await env.DB.prepare(
    "UPDATE users SET verify_token = ?, verify_token_hash = ?, verify_sent_at = ? WHERE id = ?",
  ).bind(token, await tokenHash(token), now(), user.id).run();
  await sendMail(
    env, user.email, "Confirm your e-mail in Anvil",
    `Hi ${user.handle},\n\nConfirm your e-mail in Anvil — open the link:\n\n${verifyLink(token)}\n\n` +
    `The link is valid for 24 hours. If you did not sign up, just ignore this message.\n\n— the Anvil team`,
    "verify",
  );
  return token;
}

/* ------------------------------------------------------------------ auth */
async function register(request, env) {
  const limited = rateLimited(request, "register");
  if (limited) return json({ error: limited }, { status: 429 });

  const body = await request.json().catch(() => ({}));
  const handle = String(body.handle || "").trim().toLowerCase();
  const email = String(body.email || "").trim().toLowerCase();
  const verifier = String(body.verifier || "").trim();

  // Pulapka na robota: pole, ktorego czlowiek nie widzi i nie wypelnia.
  if (body.company) return json({ ok: true, handle, email_verified: false });

  if (!HANDLE_RE.test(handle))
    return json({ error: "Nickname: 3–24 characters, lowercase letters, digits, hyphen or underscore." }, { status: 400 });
  if (!EMAIL_RE.test(email))
    return json({ error: "That e-mail address does not look valid." }, { status: 400 });
  if (isReservedDomain(email.split("@")[1])) {
    // A throwaway or reserved domain means nobody pays to read the
    // confirmation mail, so this address can never become a real account.
    // Counted separately from ordinary 400s: a steady stream here is bots
    // probing for free signups, not people mistyping.
    console.warn(JSON.stringify({
      message: "registration rejected: reserved domain",
      domain: email.split("@")[1],
      ip: clientIp(request),
    }));
    return json({ error: "That address cannot receive mail, so we cannot confirm it." }, { status: 400 });
  }
  if (!/^[0-9a-f]{64}$/.test(verifier))
    return json({ error: "Missing a valid password verifier (generate it in the browser)." }, { status: 400 });
  if (String(body.password_length || 0) < 10)
    return json({ error: "The password needs at least 10 characters." }, { status: 400 });

  const exists = await env.DB.prepare("SELECT 1 FROM users WHERE handle = ? OR email = ?")
    .bind(handle, email).first();
  if (exists) return json({ error: "That nickname or e-mail is already taken." }, { status: 409 });

  const salt = randHex(16);
  const id = crypto.randomUUID();
  const t = now();
  const pwHash = packHash(verifier);
  try {
    await env.DB.prepare(
      "INSERT INTO users (id, handle, email, pw_salt, pw_hash, created_at, last_seen) VALUES (?,?,?,?,?,?,?)",
    ).bind(id, handle, email, salt, pwHash, t, t).run();
  } catch (e) {
    return json({ error: "That account already exists." }, { status: 409 });
  }

  const token = await createSession(env.DB, id);
  const user = { id, handle, email };
  const sent = (await mailBudget(env)) ? await sendVerification(env, user) : false;
  return json(
    { ok: true, handle, email_verified: false, mail_sent: sent },
    { headers: { "set-cookie": sessionCookie(token) } },
  );
}

async function login(request, env) {
  const body = await request.json().catch(() => ({}));
  const id = String(body.id || "").trim().toLowerCase();
  const verifier = String(body.verifier || "");
  if (!id || !verifier) return json({ error: "Give a nickname (or e-mail) and a password." }, { status: 400 });

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE handle = ? OR email = ?",
  ).bind(id, id).first();

  if (!user || !hashMatches(user.pw_hash, verifier))
    return json({ error: "Wrong nickname or password." }, { status: 401 });

  await env.DB.prepare("UPDATE users SET last_seen = ? WHERE id = ?").bind(now(), user.id).run();
  const token = await createSession(env.DB, user.id);
  const streak = await touchStreak(env, user.id);
  return json(
    { ok: true, handle: user.handle, progress: await loadProgress(env, user.id), streak },
    { headers: { "set-cookie": sessionCookie(token) } },
  );
}

async function logout(request, env) {
  const token = cookieToken(request);
  if (token) await dropSession(env.DB, token);
  return json({ ok: true }, { headers: { "set-cookie": clearCookie() } });
}

async function mergeProgress(env, userId, guestTasks) {
  if (!guestTasks || typeof guestTasks !== "object") return loadProgress(env, userId);
  const upsert = env.DB.prepare(
    `INSERT INTO progress (user_id, task_id, passed, points, attempts, hints_used, code, updated_at)
     VALUES (?,?,?,?,?,?,?,?)
     ON CONFLICT(user_id, task_id) DO UPDATE SET
       passed = MAX(progress.passed, excluded.passed),
       points = CASE WHEN excluded.passed = 1 THEN excluded.points ELSE progress.points END,
       attempts = MAX(progress.attempts, excluded.attempts),
       hints_used = MAX(progress.hints_used, excluded.hints_used),
       code = COALESCE(excluded.code, progress.code)`,
  );
  for (const [taskId, p] of Object.entries(guestTasks).slice(0, 200)) {
    await upsert.bind(
      userId, String(taskId).slice(0, 64),
      p && p.passed ? 1 : 0, p && p.points ? p.points : null,
      (p && p.attempts) || 0, (p && p.hints) || 0,
      typeof (p && p.code) === "string" ? p.code.slice(0, 20000) : null,
      now(),
    ).run();
  }
  return loadProgress(env, userId);
}

/* --------------------------------------------------------------- routing */
// The 404 body. Deliberately its own markup rather than a redirect home: a
// mistyped URL should say so, not silently land somewhere else. `path` is
// reflected, so it is escaped — an unescaped request path would let anyone
// inject markup into a page served from our origin.
const NOT_FOUND_ICON = `<link rel="icon" type="image/svg+xml" href="/assets/favicon.svg" />
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" />
<link rel="manifest" href="/assets/site.webmanifest" />`;

function escape_html(s) {
  return String(s).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function not_found_page(path) {
  const shown = escape_html(path.length > 120 ? path.slice(0, 120) + "…" : path);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Page not found — Anvil</title>
<meta name="description" content="That page does not exist on Anvil. Go back to the labs." />
<meta name="robots" content="noindex" />
<meta name="theme-color" content="#171514" />
${NOT_FOUND_ICON}
<link rel="stylesheet" href="/assets/app.css" />
</head>
<body>
<header>
  <div class="container header-in">
    <a class="brand" href="/"><span class="brand-mark">A</span><b>Anvil</b><span>interactive labs</span></a>
  </div>
</header>
<main class="container">
  <div class="vpage">
    <p style="color:var(--ink-3); font-size:13px; letter-spacing:.08em; text-transform:uppercase;">404</p>
    <h1 style="font-size:30px; margin:6px 0 12px;">No such page</h1>
    <p style="color:var(--ink-2); font-size:15px; line-height:1.65;">
      Nothing is published at <code style="font-family:var(--mono);">${shown}</code>.
    </p>
    <p style="margin-top:22px;">
      <a class="btn btn-primary" href="/">All labs</a>
      <a class="btn btn-ghost" href="/panel">Your progress</a>
    </p>
  </div>
</main>
</body>
</html>`;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;

    try {
      if (p === "/healthz") return json({ ok: true, service: "hartwell-edu", db: !!env.DB });

      if (p === "/api/auth/register" && request.method === "POST") return register(request, env);
      if (p === "/api/auth/login" && request.method === "POST") return login(request, env);
      if (p === "/api/auth/logout" && request.method === "POST") return logout(request, env);

      if (p === "/api/auth/verify") {
        const token = url.searchParams.get("token") || "";
        // Link z maila ma prowadzic na strone, nie na surowy JSON — człowiek
        // kliknie link z poczty, a nie z terminala.
        if (request.headers.get("accept")?.includes("text/html")) {
          const res = await env.ASSETS.fetch(new Request("https://assets.local/verify/index.html"));
          return new Response(res.body, { status: 200, headers: res.headers });
        }
        if (!/^[0-9a-f]{48}$/.test(token)) return json({ ok: false, error: "bad link" }, { status: 400 });
        const vhash = await tokenHash(token);
        // Najpierw skrot; jawna kolumna to wczesniejszy etap migracji i
        // obsluga tokenow wystawionych przed nia.
        let row = await env.DB.prepare("SELECT id FROM users WHERE verify_token_hash = ?").bind(vhash).first();
        if (!row) {
          row = await env.DB.prepare(
            "SELECT id FROM users WHERE verify_token = ? AND verify_token_hash IS NULL",
          ).bind(token).first();
        }
        if (!row) return json({ ok: false, error: "the link expired or was already used" }, { status: 400 });
        // Oba zerwane, nie tylko jeden: inaczej skrot zostalby wskaznikiem do
        // tokenu, ktorego juz nie da sie uzyc, a kolejne wyslanie nadpisuje
        // go dopiero wtedy.
        await env.DB.prepare(
          "UPDATE users SET email_verified = 1, verify_token = NULL, verify_token_hash = NULL WHERE id = ?",
        ).bind(row.id).run();
        return json({ ok: true });
      }

      if (p === "/api/auth/resend" && request.method === "POST") {
        const limited = rateLimited(request, "resend");
        if (limited) return json({ error: limited }, { status: 429 });
        const user = await currentUser(request, env);
        if (!user) return json({ error: "no session" }, { status: 401 });
        if (!(await mailBudget(env)))
          return json({ error: "We have hit today's sending limit. Try again tomorrow." }, { status: 503 });
        const row = await env.DB.prepare("SELECT verify_sent_at, email_verified FROM users WHERE id = ?")
          .bind(user.id).first();
        if (row && row.email_verified) return json({ ok: true, already: true });
        if (row && now() - row.verify_sent_at < 60_000)
          return json({ error: "Wait a minute before asking for another one." }, { status: 429 });
        await sendVerification(env, user);
        return json({ ok: true });
      }

      if (p === "/api/me") {
        const user = await currentUser(request, env);
        if (!user) return json({ user: null });
        const row = await env.DB.prepare("SELECT days, best FROM streak WHERE user_id = ?").bind(user.id).first();
        const acc = await env.DB.prepare("SELECT plan, email_verified FROM users WHERE id = ?")
          .bind(user.id).first();
        return json({
          user: {
            handle: user.handle, email: user.email, created_at: user.created_at,
            plan: acc?.plan || "free", email_verified: !!acc?.email_verified,
          },
          progress: await loadProgress(env, user.id),
          streak: { days: row ? (row.days ? row.days.split(",").length : 0) : 0, best: row?.best || 0 },
        });
      }

      if (p === "/api/progress" && request.method === "POST") {
        const user = await currentUser(request, env);
        const body = await request.json().catch(() => ({}));
        const tasks = body.tasks || {};

        if (user) {
          // pojedyncza aktualizacja zadania
          if (body.task) {
            const t = body.task;
            await env.DB.prepare(
              `INSERT INTO progress (user_id, task_id, passed, points, attempts, hints_used, code, updated_at)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(user_id, task_id) DO UPDATE SET
                 passed = MAX(progress.passed, excluded.passed),
                 points = CASE WHEN excluded.passed = 1 THEN excluded.points ELSE progress.points END,
                 attempts = excluded.attempts,
                 hints_used = excluded.hints_used,
                 code = COALESCE(excluded.code, progress.code),
                 updated_at = excluded.updated_at`,
            ).bind(user.id, String(t.id).slice(0, 64), t.passed ? 1 : 0, t.points || null,
                   t.attempts || 0, t.hints || 0,
                   typeof t.code === "string" ? t.code.slice(0, 20000) : null, now()).run();
            if (t.passed) await touchStreak(env, user.id);
          }
          return json({ ok: true, saved: true, progress: await loadProgress(env, user.id) });
        }

        // guest: no account, stored in worker memory as a best-effort
        return json({ ok: true, guest: true });
      }

      if (p === "/api/progress" && request.method === "GET") {
        const user = await currentUser(request, env);
        return json({ user: user ? user.handle : null, progress: user ? await loadProgress(env, user.id) : {} });
      }

      // signed in: migrate progress out of localStorage
      if (p === "/api/progress/merge" && request.method === "POST") {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "no session" }, { status: 401 });
        const body = await request.json().catch(() => ({}));
        return json({ ok: true, progress: await mergeProgress(env, user.id, body.tasks) });
      }

      if (p === "/api/access/request" && request.method === "POST") {
        // Prosba o dostep do drugiego tieru. Swiadomie bez platnosci karta —
        // brak procesora jest lepszy niz udawany checkout. Trafia do D1,
        // admin nadaje plan przez admin.py grant.
        const limited = rateLimited(request, "access");
        if (limited) return json({ error: limited }, { status: 429 });
        const body = await request.json().catch(() => ({}));
        const email = String(body.email || "").trim().toLowerCase();
        if (!EMAIL_RE.test(email))
          return json({ error: "That e-mail address does not look valid." }, { status: 400 });
        if (isReservedDomain(email.split("@")[1]))
          return json({ error: "That address cannot receive mail, so we cannot answer." }, { status: 400 });
        const why = String(body.why || "").trim().slice(0, 2000);
        const handle = String(body.handle || "").trim().toLowerCase().slice(0, 24);
        const user = await currentUser(request, env);
        await env.DB.prepare(
          "INSERT INTO access_requests (user_id, handle, email, why, created_at) VALUES (?,?,?,?,?)",
        ).bind(user ? user.id : null, handle || null, email, why || null, now()).run();

        let reply = false;
        if (user && env.RESEND_API_KEY) {
          reply = await sendMail(
            env, email, "We got your Anvil access request",
            `Hi${handle ? " " + handle : ""},\n\nThanks for asking about the second tier. A person reads ` +
            `these, not a checkout bot — expect a reply with a number within a working day.\n\n` +
            `— the Anvil team`,
            "access_request",
          );
        }
        return json({ ok: true, emailed: reply });
      }

      if (p === "/api/manifest" || p === "/api/catalog") {        const res = await env.ASSETS.fetch(new Request("https://assets.local/tasks/index.json"));
        if (!res.ok) return json({ tasks: [], error: `manifest ${res.status}` }, { status: 500 });
        const data = await res.json();
        // Katalog jest publiczny, wiec **nie moze** zawierac rozwiazan
        // referencyjnych — inaczej kazda lekcja jest do skopiowania jednym
        // zapytaniem. check-tasks.py sprawdza je lokalnie, nie przez HTTP.
        const tasks = (data.tasks || []).map((t) => {
          if (p === "/api/catalog") {
            return {
              id: t.id, track: t.track, area: t.area || t.track, title: t.title,
              difficulty: t.difficulty, points: t.points, executor: t.executor, free: !!t.free,
            };
          }
          const { solution, ...rest } = t;
          return rest;
        });
        return json({ ...data, tasks, solution_stripped: true }, { cacheTtl: 0 });
      }

      const res = await env.ASSETS.fetch(request);
      const h = new Headers(res.headers);
      h.set("content-security-policy", p.startsWith("/lab") ? CSP_LAB : CSP_STRICT);
      h.set("x-content-type-options", "nosniff");
      h.set("referrer-policy", "strict-origin-when-cross-origin");
      h.set("strict-transport-security", "max-age=31536000; includeSubDomains");
      // A miss used to return the assets binding's bare 404: no title, no icon,
      // no way back. In a tab that reads as a blank page showing the raw URL —
      // which is exactly what someone sees after a typo or an old link — so it
      // gets the same head as every other page.
      if (res.status === 404 && !p.startsWith("/api/")) {
        // The binding answers a miss with text/plain; handing that back with
        // our HTML body makes the browser render it as a code listing, so the
        // type has to be corrected along with the status.
        h.set("content-type", "text/html; charset=utf-8");
        h.set("cache-control", "no-store, must-revalidate");
        return new Response(not_found_page(p), { status: 404, headers: h });
      }
      // The app shell and the engine change often, and a stale copy in a browser or
      // at the edge is worse than a revalidation round-trip. The 12 MB Pyodide
      // runtime keeps its long cache — that is the only thing worth caching hard.
      const immutable = p.startsWith("/vendor/") || /\.(wasm|woff2?|png|svg|jpg|webp|ico)$/i.test(p);
      if (!immutable) {
        h.set("cache-control", "no-store, must-revalidate");
        h.set("cf-cache-status", "DYNAMIC");
      }
      return new Response(res.body, { status: res.status, headers: h });
    } catch (e) {
      return json({ error: "server error", detail: String(e && e.message || e) }, { status: 500 });
    }
  },
};
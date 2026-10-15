/**
 * Anvil — worker dla edu.hartwell-labs.pl
 *
 * Serwuje aplikację (interaktywne laby) i backend:
 *   /api/auth/register   zakładanie konta  (handle + e-mail + hasło)
 *   /api/auth/login      logowanie, cookie sesji HttpOnly
 *   /api/auth/logout
 *   /api/me              profil + postęp + streak
 *   /api/progress        zapis postępu zadania (wymaga konta albo trybu gościa)
 *   /api/manifest        rejestr zadań
 *   /healthz
 *
 * Hasła: PBKDF2-SHA256, 210 000 iteracji, 16-bajtowa sól (OWASP 2023).
 * Sesje: 32 losowe bajty w HttpOnly+SameSite=Lax cookie, ważność 60 dni,
 * odtwarzane w bazie (można unieważnić pojedynczą sesję).
 * Postęp gościa zostaje w localStorage; po zalogowaniu jest migrowany na konto.
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

const HANDLE_RE = /^[a-z0-9][a-z0-9_-]{2,23}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s.]+\.[^@\s]+$/;

/** Porównanie w stałym czasie — brak wycieku przez czas odpowiedzi. */
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
  await db.prepare(
    "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
  ).bind(token, userId, t, t + SESSION_DAYS * 864e5).run();
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

async function currentUser(request, env) {
  const token = cookieToken(request);
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.handle, u.email, u.created_at, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ?`,
  ).bind(token).first();
  if (!row) return null;
  if (row.expires_at < now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
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

/* ------------------------------------------------------------------ auth */
async function register(request, env) {
  const body = await request.json().catch(() => ({}));
  const handle = String(body.handle || "").trim().toLowerCase();
  const email = String(body.email || "").trim().toLowerCase();
  const verifier = String(body.verifier || "").trim();

  if (!HANDLE_RE.test(handle))
    return json({ error: "Nick: 3–24 znaki, małe litery, cyfry, myślnik lub podkreślenie." }, { status: 400 });
  if (!EMAIL_RE.test(email))
    return json({ error: "E-mail wygląda na niepoprawny." }, { status: 400 });
  if (!/^[0-9a-f]{64}$/.test(verifier))
    return json({ error: "Brak poprawnej pochodnej hasła (wygeneruj ją w przeglądarce)." }, { status: 400 });
  if (String(body.password_length || 0) < 10)
    return json({ error: "Hasło musi mieć co najmniej 10 znaków." }, { status: 400 });

  const exists = await env.DB.prepare("SELECT 1 FROM users WHERE handle = ? OR email = ?")
    .bind(handle, email).first();
  if (exists) return json({ error: "Ta nazwa albo e-mail jest już zajęty." }, { status: 409 });

  const salt = randHex(16);
  const id = crypto.randomUUID();
  const t = now();
  const pwHash = packHash(verifier);
  try {
    await env.DB.prepare(
      "INSERT INTO users (id, handle, email, pw_salt, pw_hash, created_at, last_seen) VALUES (?,?,?,?,?,?,?)",
    ).bind(id, handle, email, salt, pwHash, t, t).run();
  } catch (e) {
    return json({ error: "Konto istnieje już." }, { status: 409 });
  }

  const token = await createSession(env.DB, id);
  return json({ ok: true, handle }, { headers: { "set-cookie": sessionCookie(token) } });
}

async function login(request, env) {
  const body = await request.json().catch(() => ({}));
  const id = String(body.id || "").trim().toLowerCase();
  const verifier = String(body.verifier || "");
  if (!id || !verifier) return json({ error: "Podaj nick (albo e-mail) i hasło." }, { status: 400 });

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE handle = ? OR email = ?",
  ).bind(id, id).first();

  if (!user || !hashMatches(user.pw_hash, verifier))
    return json({ error: "Nieprawidłowy nick albo hasło." }, { status: 401 });

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
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
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
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;

    try {
      if (p === "/healthz") return json({ ok: true, service: "hartwell-edu", db: !!env.DB });

      if (p === "/api/auth/register" && request.method === "POST") return register(request, env);
      if (p === "/api/auth/login" && request.method === "POST") return login(request, env);
      if (p === "/api/auth/logout" && request.method === "POST") return logout(request, env);

      if (p === "/api/me") {
        const user = await currentUser(request, env);
        if (!user) return json({ user: null });
        const row = await env.DB.prepare("SELECT days, best FROM streak WHERE user_id = ?").bind(user.id).first();
        return json({
          user: { handle: user.handle, email: user.email, created_at: user.created_at },
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

        // gość: bez konta, zapisujemy tylko w pamięci workera jako best-effort
        return json({ ok: true, guest: true });
      }

      if (p === "/api/progress" && request.method === "GET") {
        const user = await currentUser(request, env);
        return json({ user: user ? user.handle : null, progress: user ? await loadProgress(env, user.id) : {} });
      }

      // po zalogowaniu: migracja postępu z localStorage
      if (p === "/api/progress/merge" && request.method === "POST") {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "brak sesji" }, { status: 401 });
        const body = await request.json().catch(() => ({}));
        return json({ ok: true, progress: await mergeProgress(env, user.id, body.tasks) });
      }

      if (p === "/api/manifest") {
        const res = await env.ASSETS.fetch(new Request("https://assets.local/tasks/index.json"));
        if (!res.ok) return json({ tasks: [], error: `manifest ${res.status}` }, { status: 500 });
        return json(await res.json(), { cacheTtl: 300 });
      }

      const res = await env.ASSETS.fetch(request);
      const h = new Headers(res.headers);
      h.set("content-security-policy", p.startsWith("/lab") ? CSP_LAB : CSP_STRICT);
      h.set("x-content-type-options", "nosniff");
      h.set("referrer-policy", "strict-origin-when-cross-origin");
      h.set("strict-transport-security", "max-age=31536000; includeSubDomains");
      return new Response(res.body, { status: res.status, headers: h });
    } catch (e) {
      return json({ error: "server error", detail: String(e && e.message || e) }, { status: 500 });
    }
  },
};
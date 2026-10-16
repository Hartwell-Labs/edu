# Anvil — interactive labs for cybersecurity, Python, Ruby and Rust

Hartwell Labs' learning platform: **the student writes code, the code runs, and the
checker says which test did not pass.** No telemetry. An account is required, the first
ten labs are free, the second tier (lifetime) opens the full paths.

- **Site:** https://edu.hartwell-labs.pl (a Cloudflare Worker subdomain)
- **Lab:** https://edu.hartwell-labs.pl/lab
- **Your progress:** https://edu.hartwell-labs.pl/panel
- **Catalogue (JSON):** https://edu.hartwell-labs.pl/api/catalog
- **Task manifest (JSON):** https://edu.hartwell-labs.pl/api/manifest
- **AI index:** https://edu.hartwell-labs.pl/llms.txt

## Catalogue

`tools/gen_tasks.py` generates `public/tasks/index.json` from specifications
(`tools/specs_*.py`). **307 labs** in 80 areas:
186 run in the browser, 96 are quizzes, 25 need the lab VM.

Two gates before anything ships:

```bash
python3 tools/gen_tasks.py        # rebuild the catalogue (fails on a missing area)
python3 check-tasks.py            # every code lab must pass on its own solution
bash lab-vm/build.sh --test       # every lab checker must pass a good answer
                                 # ... and reject a deliberately wrong one
```

The generator refuses to write a task without an area, and `/api/manifest` strips the
`solution` field — the published catalogue never hands over a reference answer.

## How it works

| Executor | What it does | Where it runs |
|---|---|---|
| `pyodide` | Python in WebAssembly | in the student's browser; the 12 MB runtime is served from this same domain |
| `quiz` | one correct answer, no code | browser |
| `vm` | needs a kernel, a network or a compiler | downloadable lab VM, verified locally by `labcheck` |

Nothing leaves the browser for the server: code and tests run on the student's machine
and the result comes back to the engine as JSON. Guest progress lives in `localStorage`;
with an account it syncs to D1 (`anvil` database).

## Accounts and access

An account is required to open any lab — that is the whole gate. Nickname, e-mail,
password; one confirmation mail.

- **Free (the default): the first 10 labs.** They stay free.
- **Paid second tier (`plan = "lifetime"`): the remaining 297.** Sliding-window rate
  limiting, a scanner built to a spec, a safe `bpf_probe_read_user` wrapper, borrow
  checker depth, and the service you run yourself. Lifetime = one payment, no
  subscription. No price list — quoted per conversation.
- Registration sends one confirmation e-mail (Resend, `labs@hartwell-labs.pl`);
  `/api/auth/verify?token=…` marks the address confirmed. Unverified accounts get a
  banner and a "Resend" button, rate limited to one mail per minute.
- PBKDF2-SHA256 with 210 000 iterations runs **in the browser**; the server receives
  only `verifier` and compares it in constant time. Reason: Workers on the free plan
  have ~10 ms of CPU and hashing a password server-side died with exception 1101.
- Sessions: 32 random bytes in an HttpOnly, SameSite=Lax cookie, valid for 60 days,
  revocable server-side.
- Plans: `free` (ten labs) or `lifetime` (everything). Change them with
  `python3 admin.py grant <handle> lifetime`. The client checks `plan` on every task
  view; the manifest carries the `free` flag per task.

Guest progress is merged into the account on sign-in via `/api/progress/merge`.

## Tasks (16: ten free, six in the paid tier)

**Python (browser):** parsing a log line, verifying a SHA-256 digest, three layers of
encoding, detecting a SQL injection attempt. 3–5 assertions each, with a message and the
actual value.

**Cybersecurity:** name the technique in a WAF log (quiz), detect an injection, decode a
JWT and catch `alg: none`, count repeat offenders in a firewall log, sliding-window rate
limiting, redact a card number in Ruby, and a real lab VM — a service with a deliberate
misconfiguration that leaks a secret into its log.

**Rust:** predict what a program does (ownership, `move`), read a borrow-checker error
and pick the fix, and predict E0515. Executable Rust — on the lab VM, where `cargo`
exists and `labcheck` compiles your crate and runs your tests.

**Ruby:** labs on a real interpreter in the lab VM (`Enumerable`, `gsub` with a block,
masking data in logs).

## Lab VM

```bash
bash lab-vm/build.sh --host   # no QEMU: sets up labcheck and the service locally
bash lab-vm/build.sh          # qcow2 image (qemu-img, qemu-system-x86_64)
bash lab-vm/build.sh --run    # build and boot it
```

No network. `labcheck --task <id>` verifies a solution locally — the platform never sees
the code written in the VM.

## Layout

```
src/index.js              worker: security headers, /api/manifest, auth + D1 progress
public/index.html         home page
public/lab/index.html     runner
public/assets/app.js      engine: Pyodide, checker, progress, hints, accounts
public/assets/app.css     styles (consistent with hartwell-labs.pl and the wiki)
public/tasks/index.json   every task plus reference solutions
public/vendor/pyodide/    Python runtime (WASM) — self-hosted, zero CDN
public/lab-vm/            machine build script, checker, README
migrations/               D1 schema: users, sessions, progress, streak, plans
admin.py                  account admin: list, create, grant, verify, progress
check-tasks.py            verification: every task must pass on its reference solution
```

## Development

```bash
python3 check-tasks.py                 # make sure the tasks are solvable
python3 -m http.server 8080 -d public  # local preview

CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... npx wrangler deploy
```

D1 migrations:

```bash
npx wrangler d1 execute anvil --remote --file=migrations/0001_init.sql
npx wrangler d1 execute anvil --remote --file=migrations/0002_plan_email.sql
```

`anvil` is a database of its own — deliberately not the Talus licence database.

## Subdomain setup

`wrangler.toml` declares the `edu.hartwell-labs.pl` route. The CF token used for
deploys has no *Workers Domains* scope, so `custom_domain = true` gets skipped — attach
the subdomain once in the dashboard: **Workers & Pages → hartwell-edu → Settings →
Domains & Routes → Add → `edu.hartwell-labs.pl`**. After that, `npx wrangler deploy`
handles the rest.

## Roadmap

1. Ruby in the browser (Opal ~1 MB or `ruby.wasm`) — the VM then stays only for systems
   tasks and exploits.
2. Shared VM images for students (~300 MB) plus a set of ready-made machines.
3. A server-side runner for labs that need a network, with time and resource limits.
4. Custom writable tracks on request (past the free tier, priced per conversation).

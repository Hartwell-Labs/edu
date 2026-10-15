/**
 * hartwell-edu — worker dla edu.hartwell-labs.pl
 *
 * Serwuje statyczną aplikację (interaktywne laby) plus dwie rzeczy, których nie
 * da się zrobić statycznie:
 *   - /api/manifest — rejestr zadań w jednym JSON (cache 5 min)
 *   - /api/progress — postęp po anonimowym ID (bez kont, bez e-maili)
 *   - /healthz
 *
 * Postęp siedzi w pamięci workera (nie w D1): świadomy wybór na v1 — dane nie
 * są wrażliwe, a wersja trwała nie jest tu potrzebna. Migracja na D1 to jeden
 * moduł, patrz /api/progress poniżej.
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

// Lab uruchamia interpreter w przeglądarce (Pyodide / Opal z CDN), więc strona
// labu musi dopuścić skrypty i połączenia do CDN. Reszta witryny zostaje na
// polityce z hartwell-labs.pl (default-src 'none').
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

const store = new Map();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return json({ ok: true, service: "hartwell-edu" });
    }

    if (url.pathname === "/api/manifest") {
      // UWAGA: nie przekazujemy `request` jako init — Request nie jest poprawnym
      // RequestInit i worker rzucał 1101. Prosimy o asset po prostu po URL.
      const res = await env.ASSETS.fetch(new Request("https://assets.local/tasks/index.json"));
      if (!res.ok) return json({ tasks: [], error: `manifest ${res.status}` }, { status: 500 });
      return json(await res.json(), { cacheTtl: 300 });
    }

    if (url.pathname === "/api/progress") return progress(request);

    const res = await env.ASSETS.fetch(request);
    const h = new Headers(res.headers);
    h.set("content-security-policy", url.pathname.startsWith("/lab") ? CSP_LAB : CSP_STRICT);
    h.set("x-content-type-options", "nosniff");
    h.set("referrer-policy", "strict-origin-when-cross-origin");
    h.set("strict-transport-security", "max-age=31536000; includeSubDomains");
    return new Response(res.body, { status: res.status, headers: h });
  },
};

function progress(request) {
  const id = request.headers.get("x-anon") || "anon";

  if (request.method === "GET") return json({ tasks: store.get(id) || {} });

  if (request.method === "POST") {
    return request
      .json()
      .then((body) => {
        const cur = store.get(id) || {};
        store.set(id, { ...cur, ...(body.tasks || {}) });
        return json({ ok: true, saved: Object.keys(store.get(id)).length });
      })
      .catch(() => json({ ok: false }, { status: 400 }));
  }

  return json({ ok: false }, { status: 405 });
}

function json(data, opts = {}) {
  return new Response(JSON.stringify(data), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": opts.cacheTtl ? `public, max-age=${opts.cacheTtl}` : "no-store",
    },
  });
}
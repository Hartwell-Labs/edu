/**
 * Anvil — silnik labów + konta.
 *
 * Zasady:
 *  - kod i testy wykonują się u ucznia (Python w WASM przez Pyodide); serwer
 *    nigdy nie widzi kodu, który pisze,
 *  - hasła: PBKDF2-SHA256 (210k) liczy przeglądarka, serwer dostaje sam
 *    `verifier` i porównuje go w czasie stałym — Workers mają ~10 ms CPU,
 *    hashowanie po stronie serwera wywracało się wyjątkiem 1101,
 *  - postęp gościa w localStorage; po zalogowaniu migrujemy go na konto,
 *  - brak telemetrii: nick, postęp i lista rozwiązanych zadań.
 */
(function () {
  "use strict";

  var PYODIDE_BASE = "/vendor/pyodide/";
  var MARK = "@@R@@";
  var PBKDF2_ITERS = 210000;
  var KEY = "anvil:";

  var S = { tasks: [], byId: {}, cur: null, progress: {}, user: null, streak: 0, pyodide: null };
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]; }); };

  function md(s) {
    // inline: **bold**, `code`, bloki ```, listy
    var blocks = String(s || "").split(/```(\w*)\n?([\s\S]*?)```/g);
    var html = "";
    for (var i = 0; i < blocks.length; i++) {
      if (i % 3 === 2) { html += "<pre><code>" + esc(blocks[i]) + "</code></pre>"; continue; }
      if (i % 3 === 1) continue;
      html += blocks[i]
        .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
        .replace(/`([^`]+?)`/g, "<code>$1</code>")
        .split(/\n{2,}/)
        .map(function (p) {
          var lines = p.split("\n");
          if (lines.every(function (l) { return /^\s*[-*]\s+/.test(l) || !l.trim(); })) {
            return "<ul>" + lines.filter(function (l) { return l.trim(); })
              .map(function (l) { return "<li>" + l.replace(/^\s*[-*]\s+/, "") + "</li>"; }).join("") + "</ul>";
          }
          return "<p>" + lines.join("<br>") + "</p>";
        }).join("");
    }
    return html;
  }

  /* ------------------------------------------------------------- konta */
  function derive(password, id) {
    // sól jest jawna: to normalne dla haseł, a dzięki temu serwer nie musi
    // liczyć KDF (limit CPU Workers) i nigdy nie widzi hasła.
    var enc = new TextEncoder();
    return crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"])
      .then(function (key) {
        return crypto.subtle.deriveBits(
          { name: "PBKDF2", salt: enc.encode(KEY + id.toLowerCase()), iterations: PBKDF2_ITERS, hash: "SHA-256" },
          key, 256);
      })
      .then(function (bits) {
        return Array.from(new Uint8Array(bits)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
      });
  }

  function api(path, opts) {
    opts = opts || {};
    return fetch(path, {
      method: opts.method || "GET",
      headers: Object.assign({ "content-type": "application/json" }, opts.headers || {}),
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      credentials: "same-origin",
    }).then(function (r) { return r.json().catch(function () { return {}; }); });
  }

  function renderWho() {
    var el = $("who");
    if (!el) return;
    if (S.user) {
      el.innerHTML = '<a class="chip" href="/lab" title="Twój postęp"><span class="dot"></span>' +
        "<b>" + esc(S.user.handle) + "</b>" +
        (S.streak ? '<span class="streak">' + S.streak + " dni 🔥</span>" : "") + "</a>" +
        '<button class="btn btn-ghost btn-sm" id="logout">Wyloguj</button>';
      $("logout").addEventListener("click", function () {
        api("/api/auth/logout", { method: "POST" }).then(function () {
          S.user = null; S.progress = {}; saveLocal(); renderWho();
        });
      });
    } else {
      el.innerHTML = '<button class="btn btn-primary btn-sm" id="signin">Załóż konto</button>';
      $("signin").addEventListener("click", function () { openAuth(); });
    }
  }

  function openAuth(mode) {
    mode = mode || "register";
    var d = document.createElement("dialog");
    d.innerHTML =
      '<div class="dlg">' +
      '<h2 id="t"></h2><p class="sub" id="s"></p>' +
      '<div class="tabs"><button id="tab-r">Nowe konto</button><button id="tab-l">Mam konto</button></div>' +
      '<form id="f" autocomplete="on">' +
      '<div class="field" id="f-handle"><label for="i-handle">Nick</label><input id="i-handle" autocomplete="username" placeholder="np. bartosz"></div>' +
      '<div class="field" id="f-email"><label for="i-email">E-mail</label><input id="i-email" type="email" autocomplete="email" placeholder="ty@example.com"></div>' +
      '<div class="field"><label for="i-pass">Hasło</label><input id="i-pass" type="password" autocomplete="current-password" placeholder="min. 10 znaków"></div>' +
      '<div class="err" id="e"></div>' +
      '<div class="foot"><button class="btn btn-primary" id="go" type="submit"></button>' +
      '<button class="btn btn-ghost" type="button" id="cancel">Anuluj</button></div>' +
      '<p class="note">Konto trzyma tylko Twój nick, postęp i kod zadań. Bez newslettera, bez telemetrii, bez reklam. Hasło nigdy nie opuszcza przeglądarki — serwer dostaje tylko jego pochodną.</p>' +
      "</form></div>";
    document.body.appendChild(d);
    var mode_ = mode;
    var paint = function () {
      var reg = mode_ === "register";
      $("t", d).textContent = reg ? "Załóż konto" : "Wróć do nauki";
      $("s", d).textContent = reg ? "Trzy minuty, a postęp nie przepadnie po zamknięciu przeglądarki." : "Podaj nick albo e-mail i hasło.";
      $("f-handle", d).style.display = reg ? "" : "none";
      $("f-email", d).style.display = reg ? "" : "none";
      $("f-handle", d).querySelector("label").textContent = reg ? "Nick (3–24 znaki)" : "";
      $("i-pass", d).setAttribute("autocomplete", reg ? "new-password" : "current-password");
      $("go", d).textContent = reg ? "Utwórz konto" : "Zaloguj";
      $("tab-r", d).className = reg ? "on" : "";
      $("tab-l", d).className = reg ? "" : "on";
      $("e", d).textContent = "";
    };
    paint();
    d.showModal();
    $("tab-r", d).addEventListener("click", function () { mode_ = "register"; paint(); });
    $("tab-l", d).addEventListener("click", function () { mode_ = "login"; paint(); });
    $("cancel", d).addEventListener("click", function () { d.close(); d.remove(); });
    $("f", d).addEventListener("submit", function (e) {
      e.preventDefault();
      var pass = $("i-pass", d).value;
      var err = $("e", d);
      if (pass.length < 10) { err.textContent = "Hasło musi mieć co najmniej 10 znaków."; return; }
      var btn = $("go", d); btn.disabled = true; btn.textContent = "Chwilka…";
      err.textContent = "";
      var go = mode_ === "register"
        ? (function () {
            var handle = $("i-handle", d).value.trim().toLowerCase();
            var email = $("i-email", d).value.trim().toLowerCase();
            return derive(pass, handle).then(function (v) {
              return api("/api/auth/register", { method: "POST", body: { handle: handle, email: email, verifier: v, password_length: pass.length } });
            });
          })()
        : (function () {
            var id = $("i-handle", d).value.trim() || $("i-email", d).value.trim();
            return derive(pass, id).then(function (v) {
              return api("/api/auth/login", { method: "POST", body: { id: id, verifier: v } });
            });
          })();
      go.then(function (res) {
        if (res.error || !res.ok) { err.textContent = res.error || "Nie udało się."; btn.disabled = false; paint0(); return; }
        return api("/api/me").then(function (me) {
          S.user = me.user; S.progress = me.progress || {}; S.streak = (me.streak && me.streak.days) || 0;
          localStorage.removeItem(KEY + "progress:" + (me.user ? me.user.handle : "guest"));
          if (mode_ === "register") {
            return api("/api/progress/merge", { method: "POST", body: { tasks: readLocalGuest() } })
              .then(function (r) { S.progress = r.progress || S.progress; });
          }
        }).then(function () { d.close(); d.remove(); renderWho(); bootLab(); });
      }).catch(function () { err.textContent = "Coś poszło nie tak z siecią."; btn.disabled = false; });
      var paint0 = function () { btn.disabled = false; btn.textContent = mode_ === "register" ? "Utwórz konto" : "Zaloguj"; };
    });
  }

  /* ---------------------------------------------------------- postęp */
  function readLocalGuest() {
    try { return JSON.parse(localStorage.getItem(KEY + "progress:guest") || "{}"); } catch (e) { return {}; }
  }
  function saveLocal() {
    localStorage.setItem(KEY + "progress:" + (S.user ? S.user.handle : "guest"), JSON.stringify(S.progress));
  }

  function markDone(t, hints, points) {
    var s = S.progress[t.id] || (S.progress[t.id] = {});
    s.passed = true;
    s.points = Math.max(10, (t.points || 100) - hints * 25);
    s.attempts = (s.attempts || 0) + 1;
    saveLocal();
    if (S.user) {
      api("/api/progress", { method: "POST", body: { task: { id: t.id, passed: true, points: s.points, attempts: s.attempts, hints: hints, code: (S.progress[t.id] || {}).code } } })
        .then(function () { return api("/api/me"); })
        .then(function (me) { if (me.user) { S.streak = (me.streak && me.streak.days) || 0; renderWho(); renderSide(); } });
    }
    renderSide();
  }

  function saveCode(t, code) {
    var s = S.progress[t.id] || (S.progress[t.id] = {});
    s.code = code;
    saveLocal();
  }

  /* ------------------------------------------------------------ UI */
  function points(t) {
    var st = S.progress[t.id] || {};
    return Math.max(10, (t.points || 100) - (st.hints || 0) * 25);
  }

  function renderSide(filter) {
    var el = $("side");
    if (!el) return;
    var by = {};
    S.tasks.forEach(function (t) { (by[t.track] = by[t.track] || []).push(t); });
    var labels = { security: "Bezpieczeństwo", python: "Python", ruby: "Ruby", rust: "Rust" };
    var html = "";
    Object.keys(by).forEach(function (k) {
      if (filter && k !== filter) return;
      var done = by[k].filter(function (t) { return (S.progress[t.id] || {}).passed; }).length;
      html += "<h3>" + (labels[k] || k) + ' <span style="color:var(--ink-3)">' + done + "/" + by[k].length + "</span></h3>";
      by[k].forEach(function (t) {
        var st = S.progress[t.id] || {};
        var cls = "task" + (S.cur && S.cur.id === t.id ? " active" : "") + (st.passed ? " done" : "") + (st.hints ? " hinted" : "");
        html += '<button class="' + cls + '" data-id="' + t.id + '">' +
          '<span class="mark">' + (st.passed ? "✓" : st.hints ? "!" : "") + "</span>" +
          "<span>" + esc(t.title) + "</span>" +
          (t.free === false ? '<span class="lock">🔒</span>' : "") + "</button>";
      });
    });
    el.innerHTML = html;
    el.querySelectorAll(".task").forEach(function (b) {
      b.addEventListener("click", function () { open(b.getAttribute("data-id")); });
    });
  }

  function open(id) {
    var t = S.byId[id];
    if (!t) return;
    S.cur = t;
    var url = new URL(location.href);
    url.searchParams.set("task", id);
    history.replaceState(null, "", url);
    renderSide(url.searchParams.get("track"));
    var st = S.progress[id] || {};
    var labels = { security: "Bezpieczeństwo", python: "Python", ruby: "Ruby", rust: "Rust" };
    var m = $("main");
    if (!m) return;

    var head =
      '<div class="crumb">' + (labels[t.track] || t.track) + "</div>" +
      '<h1>' + esc(t.title) + "</h1>" +
      '<div class="meta"><span>' + (t.executor === "pyodide" ? "Python · WebAssembly" : t.executor === "vm" ? "maszyna labowa" : "wyjaśnienie") + "</span>" +
      "<span>trudność " + new Array(t.difficulty + 1).join("●") + "</span>" +
      "<span>" + (t.free === false ? "poza darmowym tierem" : "w darmowym tierze") + "</span>" +
      (st.passed ? '<span style="color:var(--mint);font-weight:600">✓ rozwiązane · ' + (st.points || points(t)) + " pkt</span>" : "") +
      "</div>" +
      '<div class="brief">' + md(t.brief) + "</div>";

    var body;
    if (t.free === false) {
      body = '<div class="locked"><h3>Ta ścieżka jest już poza pierwszymi dziesięcioma</h3>' +
        "<p>Nie mamy cennika — zależnie od zakresu (laby pod Twój stack, grupa prywatna, maszyna zbudowana wokół Twojej infrastruktury) ustalamy to w rozmowie. Pierwsze dziesięć labów zostaje darmowe.</p>" +
        '<a class="btn btn-primary" href="mailto:contact@hartwell-labs.pl?subject=Anvil%20labs">Zapytaj o dostęp</a></div>';
    } else if (t.executor === "quiz") {
      body = '<div class="choices" id="choices"></div><div class="out" id="out" hidden><div class="out-head" id="outhead"></div><pre id="outbody"></pre></div>';
    } else if (t.executor === "vm") {
      body = '<div class="runbar"><code class="mono" style="background:var(--bg-soft);border:1px solid var(--line);border-radius:10px;padding:10px 13px">' + esc(t.vm_check || "") + "</code>" +
        '<button class="btn btn-ghost" id="vmcheck">Sprawdź wynik</button></div>' +
        '<div class="out" id="out" hidden><div class="out-head" id="outhead"></div><pre id="outbody"></pre></div>';
    } else {
      body = '<div class="editor"><textarea class="code" id="code" spellcheck="false" aria-label="Edytor kodu">' +
        esc(st.code || t.starter || "") + "</textarea></div>" +
        '<div class="runbar">' +
        '<button class="btn btn-primary" id="run">Uruchom testy</button>' +
        '<button class="btn btn-ghost" id="reset">Wyczyść</button>' +
        '<button class="btn btn-ghost" id="hint">Podpowiedź</button>' +
        '<span class="score">Twój wynik <b id="pts">' + points(t) + "</b></span></div>" +
        '<div class="out" id="out" hidden><div class="out-head" id="outhead">gotowe</div><pre id="outbody"></pre></div>';
    }

    m.innerHTML = head + body + (st.passed && t.executor !== "quiz"
      ? '<div class="out pass" style="margin-top:18px"><div class="out-head">✓ rozwiązane</div><pre>Dobrze. Kod i wynik zapisane — możesz wrócić do tego labu, kiedy chcesz.</pre></div>'
      : "");
    wire(t);
  }

  function wire(t) {
    var code = $("code");
    if (code) code.addEventListener("input", function () { saveCode(t, code.value); });
    var run = $("run"); if (run) run.addEventListener("click", function () { runTask(t); });
    var rst = $("reset"); if (rst) rst.addEventListener("click", function () {
      code.value = t.starter || ""; saveCode(t, code.value);
      code.dispatchEvent(new Event("input"));
    });
    var hnt = $("hint"); if (hnt) hnt.addEventListener("click", function () { hint(t); });
    var vm = $("vmcheck"); if (vm) vm.addEventListener("click", function () { vmCheck(t); });
    var ch = $("choices");
    if (ch) {
      ch.innerHTML = t.choices.map(function (c, i) { return "<button data-i=\"" + i + "\">" + esc(c) + "</button>"; }).join("");
      ch.querySelectorAll("button").forEach(function (b) {
        b.addEventListener("click", function () { answer(t, +b.dataset.i, b); });
      });
    }
  }

  function hint(t) {
    var st = S.progress[t.id] || (S.progress[t.id] = {});
    var used = st.hints || 0;
    if (used >= (t.hints || []).length) return;
    st.hints = used + 1; saveLocal();
    var box = document.createElement("div");
    box.className = "hint";
    box.innerHTML = "<b>Podpowiedź " + (used + 1) + " z " + t.hints.length + " (−" + 25 * st.hints + " pkt)</b>" + md(t.hints[used]);
    $("main").appendChild(box);
    var p = $("pts"); if (p) p.textContent = points(t);
    renderSide(new URLSearchParams(location.search).get("track"));
  }

  function out(kind, text) {
    var o = $("out"); if (!o) return;
    o.hidden = false;
    o.className = "out " + (kind === "pass" ? "pass" : kind === "busy" ? "busy" : "fail");
    $("outhead").textContent = kind === "pass" ? "✓ wszystko przeszło" : kind === "busy" ? "uruchamiam" : "jeszcze nie";
    $("outbody").textContent = text;
  }

  function answer(t, i, btn) {
    var ok = (t.answer || []).indexOf(i) !== -1;
    btn.classList.add(ok ? "right" : "nope");
    if (!ok) $("choices").querySelectorAll("button").forEach(function (b) {
      if ((t.answer || []).indexOf(+b.dataset.i) !== -1) b.classList.add("right");
    });
    out(ok ? "pass" : "fail", (ok ? "Dokładnie.\n\n" : "Zobacz zaznaczoną odpowiedź.\n\n") + (t.explain || ""));
    if (ok) markDone(t, (S.progress[t.id] || {}).hints || 0);
  }

  function vmCheck(t) {
    var v = prompt("Wklej wynik polecenia z maszyny labowej:");
    if (v == null) return;
    var ok = (t.vm_accept || []).some(function (s) { return String(v).indexOf(s) !== -1; });
    out(ok ? "pass" : "fail", ok
      ? "Maszyna potwierdziła rozwiązanie. Zaliczone."
      : "To nie jest oczekiwany wynik. Zajrzyj do README maszyny labowej i spróbuj raz jeszcze.");
    if (ok) markDone(t, 0);
  }

  /* ------------------------------------------------------- wykonawcy */
  function loadPyodide() {
    if (S.pyodide) return Promise.resolve(S.pyodide);
    out("busy", "Pierwsze uruchomienie pobiera Pythona w WebAssembly (~12 MB, jednorazowo)…");
    return import(PYODIDE_BASE + "pyodide.mjs")
      .then(function (m) { return m.loadPyodide({ indexURL: PYODIDE_BASE }); })
      .then(function (py) { S.pyodide = py; return py; });
  }

  function runTask(t) {
    var src = $("code").value;
    saveCode(t, src);
    var st = S.progress[t.id] || (S.progress[t.id] = {});
    st.attempts = (st.attempts || 0) + 1; saveLocal();
    out("busy", "Uruchamiam testy…");
    loadPyodide().then(function () {
      return S.pyodide.runPythonAsync([
        "import json",
        "def check(name, ok, detail=''):",
        "    __R__.append({'name': name, 'ok': bool(ok), 'detail': str(detail)[:300]})",
        "__R__ = []",
        t.setup || "",
        src,
        "",
        t.tests || "",
        "",
        "print(" + JSON.stringify(MARK) + " + json.dumps(__R__))",
      ].join("\n"));
    }).then(function (o) {
      var text = String(o), i = text.lastIndexOf(MARK);
      if (i === -1) { out("fail", "Testy nie zgłosiły wyniku. Użyj check(...), żeby sprawdzić swoją logikę."); return; }
      var checks = JSON.parse(text.slice(i + MARK.length));
      var std = text.slice(0, i).trim();
      var failed = checks.filter(function (c) { return !c.ok; });
      var lines = checks.map(function (c) {
        return (c.ok ? "  ✓  " : "  ✗  ") + c.name + (c.detail ? "\n        " + c.detail : "");
      });
      if (std) lines.unshift("--- twoje wydruki ---\n" + std + "\n");
      if (!failed.length) { out("pass", lines.join("\n")); markDone(t, st.hints || 0); }
      else out("fail", lines.join("\n") + "\n\nPopraw i uruchom ponownie — każda iteracja to nauka, nie porażka.");
    }).catch(function (e) { out("fail", "Błąd wykonania:\n" + (e && e.message ? e.message : String(e))); });
  }

  /* ------------------------------------------------------------ start */
  function bootLab() {
    if ($("side") && S.cur) open(S.cur.id);
    else renderSide(new URLSearchParams(location.search).get("track"));
  }

  document.addEventListener("click", function (e) {
    var b = e.target.closest(".copy");
    if (!b) return;
    navigator.clipboard.writeText(b.dataset.code).then(function () {
      var t = b.textContent; b.textContent = "✓"; setTimeout(function () { b.textContent = t; }, 1400);
    });
  });

  Promise.all([
    fetch("/api/manifest").then(function (r) { return r.json(); }),
    fetch("/api/me").then(function (r) { return r.json(); }).catch(function () { return {}; }),
  ]).then(function (res) {
    var data = res[0] || {};
    S.tasks = data.tasks || [];
    S.byId = {};
    S.tasks.forEach(function (t) { S.byId[t.id] = t; });
    var me = res[1] || {};
    S.user = me.user || null;
    S.streak = (me.streak && me.streak.days) || 0;
    S.progress = S.user ? (me.progress || {}) : readLocalGuest();

    var q = new URLSearchParams(location.search);
    var want = q.get("task");
    S.cur = (want && S.byId[want]) || null;
    renderWho();
    if ($("side")) {
      renderSide(q.get("track"));
      if (S.cur) open(S.cur.id);
    }
  }).catch(function () {
    var m = $("main"); if (m) m.innerHTML = "<p>Nie udało się pobrać zadań. Sprawdź połączenie i odśwież.</p>";
  });
})();
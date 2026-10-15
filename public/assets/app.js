/**
 * Anvil — silnik labów.
 *
 * Zasada: nic nie wychodzi z przeglądarki. Kod ucznia i testy wykonują się
 * lokalnie (Pyodide dla Pythona — runtime stoi na tej samej domenie), a wynik wraca jako JSON
 * z znacznikiem @@R@@. Postęp leży w localStorage i synchronizuje się
 * z /api/progress po anonimowym identyfikatorze (bez kont).
 *
 * Wykonawcy:
 *   pyodide — Python w WASM
 *   opal    — Ruby skompilowany do JS
 *   vm      — zadanie wymagające prawdziwej maszyny (pobrana VM)
 *   quiz    — jedna odpowiedź z listy (technika, protokół, pojęcie)
 *   predict — przewiduj wyjście programu
 */
(function () {
  "use strict";

  // Runtime siedzi na tej samej domenie — na stronie firmowej nie ładujemy kodu
  // z CDN. CSP labu dopuszcza tylko 'self'.
  var PYODIDE_BASE = "/vendor/pyodide/";
  var MARK = "@@R@@";

  var state = { tasks: [], byId: {}, current: null, progress: {}, pyodide: null, opal: null };

  /* ---------------------------------------------------------- storage */
  function anonId() {
    var k = "anvil-anon";
    var v = localStorage.getItem(k);
    if (!v) { v = (crypto.randomUUID && crypto.randomUUID()) || String(Math.random()).slice(2); localStorage.setItem(k, v); }
    return v;
  }
  function loadProgress() {
    try { state.progress = JSON.parse(localStorage.getItem("anvil-progress-" + anonId()) || "{}"); }
    catch (e) { state.progress = {}; }
  }
  function saveProgress() {
    localStorage.setItem("anvil-progress-" + anonId(), JSON.stringify(state.progress));
    try {
      fetch("/api/progress", {
        method: "POST",
        headers: { "content-type": "application/json", "x-anon": anonId() },
        body: JSON.stringify({ tasks: state.progress }),
      });
    } catch (e) { /* offline — zostaje localStorage */ }
  }

  /* ----------------------------------------------------------- render */
  function el(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]; }); }
  function md(s) {
    // bardzo mały podzbiór markdown: **kod**, \`kod\`, listy, akapity
    return esc(s || "")
      .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
      .replace(/`(.+?)`/g, "<code>$1</code>")
      .split(/\n{2,}/).map(function (p) { return "<p>" + p.replace(/\n/g, " ") + "</p>"; }).join("");
  }

  function render() {
    var q = new URLSearchParams(location.search);
    var track = q.get("track");
    renderSide(track);
    var want = q.get("task");
    var cur = (want && state.byId[want]) || state.current || state.tasks[0];
    if (cur) open(cur.id);
    else el("main").innerHTML = "<p>Brak zadań.</p>";
  }

  function renderSide(filter) {
    var byTrack = {};
    state.tasks.forEach(function (t) { (byTrack[t.track] = byTrack[t.track] || []).push(t); });
    var labels = { security: "Cybersecurity", python: "Python", ruby: "Ruby", rust: "Rust" };
    var html = "";
    Object.keys(byTrack).forEach(function (k) {
      if (filter && k !== filter) return;
      html += "<h3>" + (labels[k] || k) + "</h3>";
      byTrack[k].forEach(function (t) {
        var st = state.progress[t.id];
        var cls = "task-item" + (state.current && state.current.id === t.id ? " active" : "") + (st && st.passed ? " done" : "") + (st && st.hints ? " hinted" : "");
        html += '<button class="' + cls + '" data-id="' + t.id + '">' +
          '<span class="task-dot"></span><span>' + esc(t.title) + "</span>" +
          (t.free === false ? '<span class="task-free">LOCKED</span>' : "") + "</button>";
      });
    });
    el("side").innerHTML = html;
    el("side").querySelectorAll(".task-item").forEach(function (b) {
      b.addEventListener("click", function () { open(b.getAttribute("data-id")); });
    });
  }

  function score(t) {
    var st = state.progress[t.id] || {};
    var hints = st.hints || 0;
    return Math.max(10, (t.points || 100) - hints * 25);
  }

  function open(id) {
    var t = state.byId[id];
    if (!t) return;
    state.current = t;
    var url = new URL(location.href);
    url.searchParams.set("task", id);
    history.replaceState(null, "", url);
    renderSide(url.searchParams.get("track"));

    var st = state.progress[t.id] || {};
    var main = el("main");
    var meta = '<span>' + (t.executor === "pyodide" ? "Python · WASM" : t.executor === "opal" ? "Ruby · WASM" : t.executor === "vm" ? "lab VM" : "wyjaśnienie") + "</span>" +
      '<span>trudność ' + new Array(t.difficulty + 1).join("●") + "</span>" +
      '<span>' + (t.free === false ? "poza darmowym tierem" : "w darmowym tierze") + "</span>";

    var body = "";
    if (t.free === false) {
      body = '<div class="out"><div class="out-head">locked</div><pre>' +
        esc("To zadanie jest poza pierwszymi dziesięcioma.\n\nNie mamy cennika — zależnie od zakresu (kohorty prywatne, laby pod Twój stack, lab VM zbudowany wokół Twojej infrastruktury) ustalamy to w rozmowie.\n\ncontact@hartwell-labs.pl") +
        '</pre></div><div style="margin-top:14px"><a class="btn btn-primary" href="mailto:contact@hartwell-labs.pl?subject=Anvil%20labs">Zapytaj o dostęp</a></div>';
    } else if (t.executor === "quiz") {
      body = '<div class="choice" id="choice"></div>' +
        '<div class="out" id="out" hidden><div class="out-head" id="outhead"></div><pre id="outbody"></pre></div>';
    } else if (t.executor === "vm") {
      body = md(t.brief) +
        '<div class="run-bar"><code class="mono" style="background:var(--bg-subtle);border:1px solid var(--border);border-radius:6px;padding:8px 11px">' + esc(t.vm_check || "") + '</code></div>' +
        '<div class="out" id="out" hidden><div class="out-head" id="outhead"></div><pre id="outbody"></pre></div>';
    } else if (t.executor === "pyodide" || t.executor === "opal") {
      body = md(t.brief) +
        '<div class="editor-wrap"><textarea class="code" id="code" spellcheck="false" aria-label="Edytor kodu">' + esc(st.code || t.starter || "") + "</textarea></div>" +
        '<div class="run-bar"><button class="btn btn-primary" id="run">Uruchom</button>' +
        '<button class="btn btn-secondary" id="reset">Reset</button>' +
        '<button class="btn btn-secondary" id="hint">Podpowiedź (−25 pkt)</button>' +
        '<span class="scorebar">Twój wynik <b id="pts">' + score(t) + "</b></span></div>" +
        '<div class="out" id="out" hidden><div class="out-head" id="outhead">wynik</div><pre id="outbody"></pre></div>';
    } else {
      body = md(t.brief);
    }

    main.innerHTML =
      '<div class="lab-head"><h1>' + esc(t.title) + "</h1>" +
      '<div class="lab-meta">' + meta + "</div></div>" +
      '<div class="brief">' + md(t.brief) + "</div>" + body +
      (st.passed ? '<div class="out pass" style="margin-top:16px"><div class="out-head">zaliczone</div><pre>Rozwiązanie przyjęte. Wynik: ' + (st.points || score(t)) + " pkt." + "</pre></div>" : "");

    wire(t, st);
  }

  function wire(t, st) {
    var code = el("code");
    if (code) code.addEventListener("input", function () {
      var s = state.progress[t.id] || (state.progress[t.id] = {});
      s.code = code.value;
      saveProgress();
    });
    var run = el("run"); if (run) run.addEventListener("click", function () { runTask(t); });
    var rst = el("reset"); if (rst) rst.addEventListener("click", function () { el("code").value = t.starter || ""; el("code").dispatchEvent(new Event("input")); });
    var hnt = el("hint"); if (hnt) hnt.addEventListener("click", function () { showHint(t); });
    var vm = el("vmcheck"); if (vm) vm.addEventListener("click", function () { vmTask(t); });
    var ch = el("choice");
    if (ch) ch.innerHTML = t.choices.map(function (c, i) { return "<button data-i=\"" + i + "\">" + esc(c) + "</button>"; }).join("");
    ch && ch.querySelectorAll("button").forEach(function (b) {
      b.addEventListener("click", function () { answer(t, parseInt(b.getAttribute("data-i"), 10), b); });
    });
  }

  function showHint(t) {
    var s = state.progress[t.id] || (state.progress[t.id] = {});
    var used = s.hints || 0;
    if (used >= (t.hints || []).length) return;
    s.hints = used + 1;
    saveProgress();
    var box = document.createElement("div");
    box.className = "hintbox";
    box.innerHTML = "<p><b>Podpowiedź " + (used + 1) + ":</b> " + md(t.hints[used]) + "</p>";
    el("main").appendChild(box);
    var pts = el("pts"); if (pts) pts.textContent = score(t);
  }

  function answer(t, i, btn) {
    var ok = (t.answer || []).indexOf(i) !== -1;
    btn.classList.add(ok ? "correct" : "wrong");
    if (!ok) { el("choice").querySelectorAll("button").forEach(function (b) { if ((t.answer || []).indexOf(parseInt(b.getAttribute("data-i"), 10)) !== -1) b.classList.add("correct"); }); }
    showOut(ok ? "correct" : "wrong", ok ? "Poprawnie." + (t.explain ? "\n\n" + t.explain : "") : "Nie. Poprawna odpowiedź jest zaznaczona." + (t.explain ? "\n\n" + t.explain : ""));
    if (ok) markDone(t, 0);
  }

  function markDone(t, hints) {
    var s = state.progress[t.id] || (state.progress[t.id] = {});
    s.passed = true;
    s.points = Math.max(10, (t.points || 100) - hints * 25);
    saveProgress();
    renderSide(new URLSearchParams(location.search).get("track"));
  }

  function showOut(kind, text) {
    var o = el("out"); if (!o) return;
    o.hidden = false;
    o.className = "out " + (kind === "correct" || kind === "pass" ? "pass" : "fail");
    el("outhead").textContent = kind === "correct" || kind === "pass" ? "accepted" : kind === "busy" ? "running" : "failed";
    el("outbody").textContent = text;
  }

  /* ---------------------------------------------------------- runtimes */
  function loadScript(src) {
    return new Promise(function (res, rej) {
      var s = document.createElement("script");
      s.src = src; s.onload = res; s.onerror = function () { rej(new Error("nie udało się załadować " + src)); };
      document.head.appendChild(s);
    });
  }

  function ensurePyodide() {
    if (state.pyodide) return Promise.resolve(state.pyodide);
    showOut("busy", "Pobieram Pythona w WebAssembly (jednorazowo, ~12 MB)…");
    return import(PYODIDE_BASE + "pyodide.mjs")
      .then(function (mod) {
        return mod.loadPyodide({ indexURL: PYODIDE_BASE });
      })
      .then(function (py) { state.pyodide = py; return py; });
  }

  function runTask(t) {
    var src = el("code").value;
    var s = state.progress[t.id] || (state.progress[t.id] = {});
    s.code = src;
    saveProgress();
    showOut("busy", "Uruchamiam…");
    ensurePyodide()
      .then(function () { return runPython(src, t.tests, t.setup); })
      .then(function (r) { grade(t, r); })
      .catch(function (e) { showOut("fail", "Błąd wykonania:\n" + (e && e.message ? e.message : String(e))); });
  }

  function runPython(user, tests, setup) {
    return state.pyodide.runPythonAsync([
      "import json, sys",
      "def check(name, ok, detail=''):",
      "    __R__.append({'name': name, 'ok': bool(ok), 'detail': str(detail)[:300]})",
      "__R__ = []",
      setup || "",
      user,
      "",
      tests || "",
      "",
      "print(" + JSON.stringify(MARK) + " + json.dumps(__R__))"
    ].join("\n")).then(function (out) { return parse(out); });
  }

  function parse(text) {
    var i = String(text).lastIndexOf(MARK);
    if (i === -1) return { checks: [], stdout: text };
    return { checks: JSON.parse(text.slice(i + MARK.length)), stdout: text.slice(0, i) };
  }

  function grade(t, r) {
    var checks = r.checks || [];
    var failed = checks.filter(function (c) { return !c.ok; });
    var lines = checks.map(function (c) { return (c.ok ? "  PASS  " : "  FAIL  ") + c.name + (c.detail ? "\n        " + c.detail : ""); });
    if (r.stdout && r.stdout.trim()) lines.unshift("--- stdout ---\n" + r.stdout.trim() + "\n");
    if (!checks.length) { showOut("fail", "Testy nie zgłosiły żadnego wyniku. Uruchom `check(...)` w swoim kodzie.\n\n" + r.stdout); return; }
    if (!failed.length) {
      showOut("pass", lines.join("\n"));
      var st = state.progress[t.id] || {};
      markDone(t, st.hints || 0);
    } else {
      showOut("fail", lines.join("\n"));
    }
  }

  function vmTask(t) {
    showOut("busy", "To zadanie sprawdza się na maszynie wirtualnej.\n\n" + (t.vm_check || "") + "\n\nUruchom w lab VM i wklej tutaj wynik:");
    var v = prompt("Wklej wynik komendy weryfikującej:");
    if (v == null) return;
    var ok = (t.vm_accept || []).some(function (s) { return String(v).indexOf(s) !== -1; });
    showOut(ok ? "pass" : "fail", ok ? "Zaliczone — maszyna zrobiła to, co trzeba." : "Nie pasuje. Sprawdź, czy skonfigurowałeś usługę zgodnie z briefem.");
    if (ok) markDone(t, 0);
  }

  /* --------------------------------------------------------------- boot */
  fetch("/api/manifest")
    .then(function (r) { return r.json(); })
    .then(function (data) {
      state.tasks = data.tasks || [];
      state.byId = {};
      state.tasks.forEach(function (t) { state.byId[t.id] = t; });
      loadProgress();
      render();
    })
    .catch(function () { el("main").innerHTML = "<p>Nie udało się pobrać zadań. Sprawdź połączenie.</p>"; });
})();
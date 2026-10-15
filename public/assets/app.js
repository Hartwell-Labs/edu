/**
 * Anvil — lab engine + accounts.
 *
 * Rules:
 *  - code and tests run on the student's machine (Python via Pyodide/WASM); the
 *    server never sees the code being written,
 *  - passwords: the browser runs PBKDF2-SHA256 (210k) and sends only the
 *    `verifier`; the server compares it in constant time — Workers have ~10 ms
 *    of CPU and hashing server-side died with exception 1101,
 *  - guest progress lives in localStorage; on sign-in it is merged into the
 *    account,
 *  - no telemetry: nickname, progress and the list of solved tasks.
 */
(function () {
  "use strict";

  var PYODIDE_BASE = "/vendor/pyodide/";
  var MARK = "@@R@@";
  var PBKDF2_ITERS = 210000;
  var KEY = "anvil:";
  var TRACK_LABELS = { security: "Cybersecurity", python: "Python", ruby: "Ruby", rust: "Rust" };

  var S = { tasks: [], byId: {}, cur: null, progress: {}, user: null, streak: 0, pyodide: null };
  var $ = function (id, root) { return (root || document).getElementById(id); };
  var esc = function (s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]; }); };

  /** Premium (plan !== free) opens the tasks past the free ten. */
  function unlocked(t) { return t.free !== false || (S.user && S.user.plan && S.user.plan !== "free"); }

  function md(s) {
    // inline: **bold**, `code`, fenced blocks, bullet lists
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

  /* ------------------------------------------------------------- accounts */
  function derive(password, id) {
    // The salt is public, as salts are for passwords — and it means the server
    // runs no KDF (Workers CPU limit) and never sees the password.
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

  function refreshMe() {
    return api("/api/me").then(function (me) {
      S.user = me.user || null;
      S.streak = (me.streak && me.streak.days) || 0;
      if (S.user) S.progress = me.progress || {};
      renderWho();
      renderBanner();
      renderSide(trackParam());
      return me;
    });
  }

  function renderWho() {
    var el = $("who");
    if (!el) return;
    if (S.user) {
      var plan = S.user.plan && S.user.plan !== "free"
        ? '<span class="streak" title="Lifetime access">' + esc(S.user.plan) + "</span>"
        : (S.user.email_verified ? "" : '<span class="warndot" title="E-mail not confirmed">!</span>');
      el.innerHTML = '<a class="chip" href="/lab" title="Your progress"><span class="dot"></span>' +
        "<b>" + esc(S.user.handle) + "</b>" +
        (S.streak ? '<span class="streak">' + S.streak + "d 🔥</span>" : "") + plan + "</a>" +
        '<button class="btn btn-ghost btn-sm" id="logout">Sign out</button>';
      $("logout").addEventListener("click", function () {
        api("/api/auth/logout", { method: "POST" }).then(function () {
          S.user = null; S.progress = readLocalGuest(); renderWho(); renderBanner();
          renderSide(trackParam()); if (S.cur) open(S.cur.id);
        });
      });
    } else {
      el.innerHTML = '<button class="btn btn-primary btn-sm" id="signin">Create account</button>';
      $("signin").addEventListener("click", function () { openAuth(); });
    }
  }

  /* --------------------------------------------- e-mail confirmation banner */
  function renderBanner(msg) {
    var slot = $("banner-slot");
    if (!slot) return;
    if (!S.user || S.user.email_verified) { slot.innerHTML = msg ? '<div class="banner info">' + esc(msg) + "</div>" : ""; return; }
    slot.innerHTML =
      '<div class="banner"><span class="banner-ic">✉</span>' +
      "<span><b>Confirm your e-mail.</b> We sent a link to " + esc(S.user.email) +
      ". Open it and your progress follows you to any device.</span>" +
      '<button class="btn btn-ghost btn-sm" id="resend">Resend</button></div>';
    $("resend").addEventListener("click", function () {
      var b = this; b.disabled = true; b.textContent = "Sending…";
      api("/api/auth/resend", { method: "POST" }).then(function (r) {
        b.textContent = "Sent";
        if (r.error) { slot.firstChild.querySelector("span:nth-child(2)").innerHTML =
          "<b>" + esc(r.error) + "</b>"; }
      });
    });
  }

  function openAuth(mode) {
    mode = mode || "register";
    var d = document.createElement("dialog");
    d.innerHTML =
      '<div class="dlg">' +
      '<h2 id="t"></h2><p class="sub" id="s"></p>' +
      '<div class="tabs"><button id="tab-r">New account</button><button id="tab-l">I have an account</button></div>' +
      '<form id="f" autocomplete="on">' +
      '<div class="field" id="f-handle"><label for="i-handle">Nickname</label><input id="i-handle" autocomplete="username" placeholder="e.g. kija"></div>' +
      '<div class="field" id="f-email"><label for="i-email">E-mail</label><input id="i-email" type="email" autocomplete="email" placeholder="you@example.com"></div>' +
      '<div class="field"><label for="i-pass">Password</label><input id="i-pass" type="password" autocomplete="current-password" placeholder="at least 10 characters"></div>' +
      '<div class="err" id="e"></div>' +
      '<div class="foot"><button class="btn btn-primary" id="go" type="submit"></button>' +
      '<button class="btn btn-ghost" type="button" id="cancel">Cancel</button></div>' +
      "<p class=\"note\">An account stores only your nickname, your progress and your code. No newsletter, no telemetry, no ads. Your password never leaves the browser — the server receives only a derivative of it. We e-mail you once, to confirm the address.</p>" +
      "</form></div>";
    document.body.appendChild(d);
    var mode_ = mode;
    var paint = function () {
      var reg = mode_ === "register";
      $("t", d).textContent = reg ? "Create your account" : "Welcome back";
      $("s", d).textContent = reg ? "Three minutes, and your progress survives closing the browser." : "Enter your nickname or e-mail and your password.";
      $("f-handle", d).querySelector("label").textContent = reg ? "Nickname (3–24 characters)" : "Nickname or e-mail";
      $("f-email", d).querySelector("label").textContent = "E-mail";
      $("i-pass", d).setAttribute("autocomplete", reg ? "new-password" : "current-password");
      $("go", d).textContent = reg ? "Create account" : "Sign in";
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
      if (pass.length < 10) { err.textContent = "The password needs at least 10 characters."; return; }
      var btn = $("go", d); btn.disabled = true; btn.textContent = "One moment…";
      err.textContent = "";
      var guest = readLocalGuest();
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
        if (res.error || !res.ok) { err.textContent = res.error || "Something went wrong."; btn.disabled = false; paint(); return; }
        // postęp zapisany w przeglądarce wędruje na konto (także przy samym logowaniu)
        if (Object.keys(guest).length) {
          return api("/api/progress/merge", { method: "POST", body: { tasks: guest } });
        }
      }).then(function () {
        d.close(); d.remove();
        return refreshMe().then(function () { if (S.cur) open(S.cur.id); });
      }).catch(function () { err.textContent = "Network trouble — try again."; btn.disabled = false; paint(); });
    });
  }

  /* ---------------------------------------------------------- progress */
  function readLocalGuest() {
    try { return JSON.parse(localStorage.getItem(KEY + "progress:guest") || "{}"); } catch (e) { return {}; }
  }
  function saveLocal() {
    localStorage.setItem(KEY + "progress:" + (S.user ? S.user.handle : "guest"), JSON.stringify(S.progress));
  }
  function trackParam() { return new URLSearchParams(location.search).get("track"); }

  function markDone(t, hints, points) {
    var s = S.progress[t.id] || (S.progress[t.id] = {});
    s.passed = true;
    s.points = Math.max(10, (t.points || 100) - hints * 25);
    s.attempts = (s.attempts || 0) + 1;
    saveLocal();
    if (S.user) {
      api("/api/progress", { method: "POST", body: { task: { id: t.id, passed: true, points: s.points, attempts: s.attempts, hints: hints, code: s.code } } })
        .then(function () { return api("/api/me"); })
        .then(function (me) {
          if (!me.user) return;
          S.streak = (me.streak && me.streak.days) || 0;
          renderWho(); renderBanner(); renderSide(trackParam());
        });
    }
    renderSide(trackParam());
  }

  function saveCode(t, code) {
    var s = S.progress[t.id] || (S.progress[t.id] = {});
    s.code = code;
    saveLocal();
  }

  /* --------------------------------------------------------------- UI */
  function points(t) {
    var st = S.progress[t.id] || {};
    return Math.max(10, (t.points || 100) - (st.hints || 0) * 25);
  }

  function renderSide(filter) {
    var el = $("side");
    if (!el) return;
    var by = {};
    S.tasks.forEach(function (t) { (by[t.track] = by[t.track] || []).push(t); });
    var html = "";
    Object.keys(by).forEach(function (k) {
      if (filter && k !== filter) return;
      var open = by[k].filter(unlocked);
      var done = by[k].filter(function (t) { return (S.progress[t.id] || {}).passed; }).length;
      html += "<h3>" + (TRACK_LABELS[k] || k) + ' <span class="side-count">' + done + "/" + open.length + "</span></h3>";
      by[k].forEach(function (t) {
        var st = S.progress[t.id] || {};
        var lock = unlocked(t) ? "" : '<span class="lock">🔒</span>';
        var cls = "task" + (S.cur && S.cur.id === t.id ? " active" : "") + (st.passed ? " done" : "") + (st.hints ? " hinted" : "");
        html += '<button class="' + cls + '" data-id="' + t.id + '">' +
          '<span class="mark">' + (st.passed ? "✓" : st.hints ? "!" : "") + "</span>" +
          "<span>" + esc(t.title) + "</span>" + lock + "</button>";
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
    renderSide(trackParam());
    var st = S.progress[id] || {};
    var m = $("main");
    if (!m) return;

    var kind = t.executor === "pyodide" ? "Python · WebAssembly" : t.executor === "vm" ? "lab machine" : "read and answer";
    var tier = unlocked(t)
      ? '<span>' + (t.free === false ? "full track" : "in the free tier") + "</span>"
      : '<span class="tier-locked">past the free ten</span>';

    var head =
      '<div class="crumb">' + (TRACK_LABELS[t.track] || t.track) + "</div>" +
      "<h1>" + esc(t.title) + "</h1>" +
      '<div class="meta"><span>' + kind + "</span>" +
      "<span>difficulty " + new Array(t.difficulty + 1).join("●") + "</span>" + tier +
      (st.passed ? '<span class="done-note">✓ solved · ' + (st.points || points(t)) + " pts</span>" : "") +
      "</div>" +
      '<div class="brief">' + md(t.brief) + "</div>";

    var body;
    if (!unlocked(t)) {
      body = '<div class="locked"><h3>This one is past the first ten</h3>' +
        "<p>We publish no price list — depending on scope (labs for your stack, a private group, a machine built around your infrastructure) we agree it in a conversation. The first ten labs stay free.</p>" +
        '<a class="btn btn-primary" href="mailto:contact@hartwell-labs.pl?subject=Anvil%20labs">Ask about access</a></div>';
    } else if (t.executor === "quiz") {
      body = '<div class="choices" id="choices"></div><div class="out" id="out" hidden><div class="out-head" id="outhead"></div><pre id="outbody"></pre></div>';
    } else if (t.executor === "vm") {
      body = '<div class="runbar"><code class="vmcmd">' + esc(t.vm_check || "") + "</code>" +
        '<button class="btn btn-ghost" id="vmcheck">Check the result</button></div>' +
        '<div class="out" id="out" hidden><div class="out-head" id="outhead"></div><pre id="outbody"></pre></div>';
    } else {
      body = '<div class="editor"><textarea class="code" id="code" spellcheck="false" aria-label="Code editor">' +
        esc(st.code || t.starter || "") + "</textarea></div>" +
        '<div class="runbar">' +
        '<button class="btn btn-primary" id="run">Run the tests</button>' +
        '<button class="btn btn-ghost" id="reset">Clear</button>' +
        '<button class="btn btn-ghost" id="hint">Hint</button>' +
        '<span class="score">Available <b id="pts">' + points(t) + "</b></span></div>" +
        '<div class="out" id="out" hidden><div class="out-head" id="outhead">ready</div><pre id="outbody"></pre></div>';
    }

    m.innerHTML = head + body + (st.passed && t.executor !== "quiz"
      ? '<div class="out pass" style="margin-top:18px"><div class="out-head">✓ solved</div><pre>Saved. Come back to this lab whenever you want.</pre></div>'
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
      ch.innerHTML = t.choices.map(function (c, i) { return "<button data-i=\"" + i + "\">" + md(c) + "</button>"; }).join("");
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
    box.innerHTML = "<b>Hint " + (used + 1) + " of " + t.hints.length + " (−" + 25 * st.hints + " pts)</b>" + md(t.hints[used]);
    $("main").appendChild(box);
    var p = $("pts"); if (p) p.textContent = points(t);
    renderSide(trackParam());
  }

  function out(kind, text) {
    var o = $("out"); if (!o) return;
    o.hidden = false;
    o.className = "out " + (kind === "pass" ? "pass" : kind === "busy" ? "busy" : "fail");
    $("outhead").textContent = kind === "pass" ? "✓ everything passed" : kind === "busy" ? "running" : "not yet";
    $("outbody").textContent = text;
  }

  function answer(t, i, btn) {
    var ok = (t.answer || []).indexOf(i) !== -1;
    btn.classList.add(ok ? "right" : "nope");
    if (!ok) $("choices").querySelectorAll("button").forEach(function (b) {
      if ((t.answer || []).indexOf(+b.dataset.i) !== -1) b.classList.add("right");
    });
    out(ok ? "pass" : "fail", (ok ? "Exactly.\n\n" : "Look at the highlighted answer.\n\n") + (t.explain || ""));
    if (ok) markDone(t, (S.progress[t.id] || {}).hints || 0);
  }

  function vmCheck(t) {
    var v = prompt("Paste the output of the command from the lab machine:");
    if (v == null) return;
    var ok = (t.vm_accept || []).some(function (s) { return String(v).indexOf(s) !== -1; });
    out(ok ? "pass" : "fail", ok
      ? "The lab machine confirmed your solution. Marked as solved."
      : "That is not the expected output. Read the lab machine README and try again.");
    if (ok) markDone(t, 0);
  }

  /* ---------------------------------------------------------- executors */
  function loadPyodide() {
    if (S.pyodide) return Promise.resolve(S.pyodide);
    out("busy", "The first run downloads Python compiled to WebAssembly (~12 MB, once)…");
    return import(PYODIDE_BASE + "pyodide.mjs")
      .then(function (m) { return m.loadPyodide({ indexURL: PYODIDE_BASE }); })
      .then(function (py) { S.pyodide = py; return py; });
  }

  function runTask(t) {
    var src = $("code").value;
    saveCode(t, src);
    var st = S.progress[t.id] || (S.progress[t.id] = {});
    st.attempts = (st.attempts || 0) + 1; saveLocal();
    out("busy", "Running the tests…");
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
      if (i === -1) { out("fail", "The tests reported nothing. Use check(...) to verify your own logic."); return; }
      var checks = JSON.parse(text.slice(i + MARK.length));
      var std = text.slice(0, i).trim();
      var failed = checks.filter(function (c) { return !c.ok; });
      var lines = checks.map(function (c) {
        return (c.ok ? "  ✓  " : "  ✗  ") + c.name + (c.detail ? "\n        " + c.detail : "");
      });
      if (std) lines.unshift("--- your prints ---\n" + std + "\n");
      if (!failed.length) { out("pass", lines.join("\n")); markDone(t, st.hints || 0); }
      else out("fail", lines.join("\n") + "\n\nFix it and run again — every iteration is learning, not failure.");
    }).catch(function (e) { out("fail", "Execution error:\n" + (e && e.message ? e.message : String(e))); });
  }

  /* --------------------------------------------------------------- start */
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

    var want = new URLSearchParams(location.search).get("task");
    S.cur = (want && S.byId[want]) || null;
    renderWho();
    renderBanner();
    if ($("side")) {
      renderSide(trackParam());
      if (S.cur) open(S.cur.id);
    }
  }).catch(function () {
    var m = $("main"); if (m) m.innerHTML = "<p>Could not load the tasks. Check your connection and refresh.</p>";
  });
})();

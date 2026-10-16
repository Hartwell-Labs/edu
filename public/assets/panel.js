/**
 * Anvil — panel postepu.
 *
 * Panel liczy wszystko po stronie klienta z dwóch zrodel: /api/catalog
 * (katalog bez rozwiazan) i /api/me (konto, postep, seria dni). Dzieki
 * temu dziala natychmiast, nie wymaga zapytania do bazy i pokazuje dokladnie
 * to, co serwer zapisal — a nie to, co chcialibysmy zapiszyc.
 */
(function () {
  "use strict";

  var TRACK_LABELS = { security: "Cybersecurity", python: "Python", ruby: "Ruby", rust: "Rust" };
  var EXECUTOR_LABELS = { pyodide: "in your browser", vm: "on the lab machine", quiz: "read and answer" };
  var S = { catalog: [], byId: {}, me: null };

  var $ = function (id) { return document.querySelector("#" + id); };
  var esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c];
    });
  };

  function api(path) {
    return fetch(path, { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .catch(function () { return {}; });
  }

  /* ------------------------------------------------------------ liczby */
  function stats(progress) {
    var out = {
      total: S.catalog.length,
      solved: 0, started: 0, points: 0, possible: 0, hints: 0, attempts: 0,
      freeSolved: 0, freeTotal: 0, paidSolved: 0, paidTotal: 0,
      byTrack: {}, byArea: {}, byExecutor: {},
    };
    S.catalog.forEach(function (t) {
      var st = progress[t.id] || {};
      var track = out.byTrack[t.track] = out.byTrack[t.track] ||
        { label: TRACK_LABELS[t.track] || t.track, total: 0, solved: 0, points: 0, free: 0, freeSolved: 0 };
      var area = out.byArea[t.area || t.track] = out.byArea[t.area || t.track] ||
        { label: t.area || t.track, total: 0, solved: 0 };
      var ex = out.byExecutor[t.executor] = out.byExecutor[t.executor] ||
        { label: EXECUTOR_LABELS[t.executor] || t.executor, total: 0, solved: 0 };

      out.possible += t.points || 0;
      track.total++; area.total++; ex.total++;
      if (t.free) { out.freeTotal++; track.free++; } else { out.paidTotal++; }

      if (st.passed) {
        out.solved++; out.points += st.points || 0;
        track.solved++; track.points += st.points || 0;
        area.solved++; ex.solved++;
        if (t.free) { out.freeSolved++; track.freeSolved++; }
        else out.paidSolved++;
      } else if (st.attempts || st.code) {
        out.started++;
      }
      out.hints += st.hints || 0;
      out.attempts += st.attempts || 0;
    });
    return out;
  }

  function pct(done, total) { return total ? Math.round((done / total) * 100) : 0; }

  function bar(done, total, label) {
    var p = pct(done, total);
    // Jeden lab na 307 to 0,3% — pasek o szerokosci 0 wygladzalby jak blad.
    var w = p > 0 ? Math.max(p, 1.5) : 0;
    return '<div class="pbar" title="' + esc(label || (done + " of " + total)) + '">'
      + '<span style="width:' + w + '%"></span></div>'
      + '<span class="pbar-n">' + done + "/" + total + "</span>";
  }

  function streak() {
    return (S.me && S.me.streak) || { days: 0, best: 0 };
  }

  /* --------------------------------------------------------------- UI */
  function renderHeader() {
    var el = $("who");
    if (!el) return;
    if (S.me && S.me.user) {
      el.innerHTML = '<a class="chip" href="/panel"><span class="dot"></span><b>'
        + esc(S.me.user.handle) + "</b>"
        + (streak().days ? '<span class="streak">' + streak().days + "d 🔥</span>" : "")
        + "</a>"
        + '<button class="btn btn-ghost btn-sm" id="logout">Sign out</button>';
      $("logout").addEventListener("click", function () {
        api("/api/auth/logout").then(function () { location.href = "/"; });
      });
    } else {
      el.innerHTML = '<a class="btn btn-primary btn-sm" href="/lab">Sign in</a>';
    }
  }

  function renderBanner() {
    var slot = $("banner-slot");
    if (!slot) return;
    if (!S.me || !S.me.user || S.me.user.email_verified) { slot.innerHTML = ""; return; }
    slot.innerHTML = '<div class="banner"><span class="banner-ic">✉</span>'
      + "<span><b>Confirm your e-mail.</b> Your progress is saved, but an unconfirmed address "
      + "cannot recover an account. We sent a link to " + esc(S.me.user.email) + ".</span></div>";
  }

  function gate() {
    $("panel").innerHTML =
      '<div class="gate"><span class="kicker">Your progress lives in an account</span>'
      + "<h1>Sign in to see your progress</h1>"
      + '<p class="lede" style="margin:14px 0 22px">Without an account your progress stays in this '
      + "browser and disappears when you clear it. With one it follows you to any device — and it is "
      + 'what the second tier checks against.</p>'
      + '<div class="gate-actions"><a class="btn btn-primary" href="/lab">Go to the labs</a></div>'
      + "</div>";
  }

  function solveList(progress) {
    var rows = S.catalog.filter(function (t) { return (progress[t.id] || {}).passed; })
      .map(function (t) {
        var st = progress[t.id];
        var hints = st.hints || 0;
        return "<tr><td><a href=\"/lab?task=" + encodeURIComponent(t.id) + "\">" + esc(t.title) + "</a>"
          + '<span class="mut">' + esc(TRACK_LABELS[t.track] || t.track) + " · " + esc(t.area || t.track) + "</span></td>"
          + '<td class="num">' + (st.points || 0) + "</td>"
          + '<td class="num">' + (st.attempts || 0) + "</td>"
          + '<td class="num">' + hints + "</td></tr>";
      });
    if (!rows.length) return '<p class="mut">Nothing solved yet. <a href="/lab">Start the first lab →</a></p>';
    return '<table class="ptable"><thead><tr><th>Lab</th><th class="num">points</th>'
      + '<th class="num">tries</th><th class="num">hints</th></tr></thead><tbody>'
      + rows.join("") + "</tbody></table>";
  }

  function inProgress(progress) {
    var rows = S.catalog.filter(function (t) {
      var st = progress[t.id] || {};
      return !st.passed && (st.attempts || st.code);
    }).map(function (t) {
      var st = progress[t.id];
      return "<li><a href=\"/lab?task=" + encodeURIComponent(t.id) + "\">" + esc(t.title) + "</a>"
        + '<span class="mut">' + (st.attempts || 0) + " tries · " + (st.hints || 0) + " hints</span></li>";
    });
    if (!rows.length) return "";
    return "<h3>Still open</h3><ul class=\"plist\">" + rows.join("") + "</ul>";
  }

  function nextUp(progress) {
    var free = S.catalog.filter(function (t) { return t.free && !(progress[t.id] || {}).passed; });
    if (!free.length) return '<p class="mut">Every free lab is solved. The rest is the second tier.</p>';
    var t = free[0];
    return '<a class="nxt" href="/lab?task=' + encodeURIComponent(t.id) + '">'
      + '<span class="kicker">Next up</span><b>' + esc(t.title) + "</b>"
      + "<span>" + esc(TRACK_LABELS[t.track] || t.track) + " · " + t.points + " pts</span></a>";
  }

  function trackRows(st) {
    return Object.keys(st.byTrack).sort(function (a, b) {
      return st.byTrack[b].total - st.byTrack[a].total;
    }).map(function (k) {
      var t = st.byTrack[k];
      return "<tr><td>" + esc(t.label)
        + '<span class="mut">' + t.freeSolved + "/" + t.free + " free</span></td>"
        + "<td>" + bar(t.solved, t.total) + "</td>"
        + '<td class="num">' + t.points + "</td></tr>";
    }).join("");
  }

  function areaRows(st) {
    var keys = Object.keys(st.byArea).sort(function (a, b) {
      // Najpierw tam, gdzie cos juz zrobiles, potem reszta wg wielkosci.
      if (st.byArea[b].solved !== st.byArea[a].solved) return st.byArea[b].solved - st.byArea[a].solved;
      return st.byArea[b].total - st.byArea[a].total;
    });
    var TOP = 12;
    var head = keys.slice(0, TOP);
    var tail = keys.slice(TOP);
    var rows = head.map(function (k) { return areaRow(st, k); });
    if (tail.length) {
      var done = tail.reduce(function (n, k) { return n + st.byArea[k].solved; }, 0);
      var total = tail.reduce(function (n, k) { return n + st.byArea[k].total; }, 0);
      rows.push('<tr><td>' + tail.length + " more areas</td>"
        + "<td>" + bar(done, total) + "</td>"
        + '<td class="num">' + pct(done, total) + "%</td></tr>");
    }
    return rows.join("");
  }

  function areaRow(st, k) {
    var a = st.byArea[k];
    return "<tr><td>" + esc(a.label) + "</td>"
      + "<td>" + bar(a.solved, a.total) + "</td>"
      + '<td class="num">' + pct(a.solved, a.total) + "%</td></tr>";
  }

  function render() {
    if (!S.me || !S.me.user) { gate(); return; }
    var progress = S.me.progress || {};
    var st = stats(progress);
    var u = S.me.user;
    var isPaid = u.plan && u.plan !== "free";
    var created = u.created_at ? new Date(u.created_at).toISOString().slice(0, 10) : null;

    var done = st.solved === st.total;
    var badge = done ? "Every lab solved. That is the whole catalogue."
      : (st.solved >= 10 ? "Ten labs done — the free tier is behind you."
        : (st.solved > 0 ? "A good start. Ten free labs open the second tier."
          : "Nothing solved yet — the first lab takes about ten minutes."));

    $("panel").innerHTML =
      '<div class="p-head">'
      + '<div><span class="kicker">Your progress</span><h1>' + esc(u.handle) + "</h1>"
      + '<p class="lede" style="margin-top:6px">' + badge + "</p></div>"
      + '<div class="p-plan">' + (isPaid
        ? '<span class="tier-full">second tier · ' + esc(u.plan) + "</span>"
        : '<button class="btn btn-ghost btn-sm" id="ask-plan">Request the second tier</button>')
      + (u.email_verified ? "" : '<span class="warndot" title="E-mail not confirmed">!</span>')
      + (created ? '<span class="mut">joined ' + created + "</span>" : "")
      + "</div></div>"

      + '<div class="p-stats">'
      + stat(st.solved + "/" + st.total, "labs solved", st.total ? pct(st.solved, st.total) + "%" : "—")
      + stat(st.points, "points earned", "of " + st.possible)
      + stat(streak().days + "d", "day streak", streak().best + "d best")
      + stat(st.freeSolved + "/" + st.freeTotal, "free tier", isPaid ? "opened" : "open")
      + "</div>"

      + nextUp(progress)

      + '<div class="p-cols">'
      + '<div><h3>Paths</h3><table class="ptable"><tbody>' + trackRows(st) + "</tbody></table></div>"
      + '<div><h3>Where the time goes</h3><table class="ptable"><tbody>' + areaRows(st) + "</tbody></table></div>"
      + "</div>"

      + inProgress(progress)

      + "<h3>Solved</h3>" + solveList(progress)

      + '<p class="p-foot">Your code and progress live in your account only. '
      + 'Nothing is sold, shared or sent anywhere else. <button class="linkbtn" id="export">Download your progress as JSON</button></p>';

    var ask = $("ask-plan");
    if (ask) ask.addEventListener("click", function () { openAccessDialog(); });

    var ex = $("export");
    if (ex) ex.addEventListener("click", function () {
      var blob = new Blob([JSON.stringify({
        handle: u.handle, exported: new Date().toISOString(),
        stats: st, progress: progress,
      }, null, 2)], { type: "application/json" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "anvil-progress-" + u.handle + ".json";
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
    });
  }

  function stat(value, label, sub) {
    return '<div class="pstat"><b>' + esc(value) + "</b><span>" + esc(label) + "</span>"
      + (sub ? '<i>' + esc(sub) + "</i>" : "") + "</div>";
  }

  /* --------------------------------------------------------------- start */
  Promise.all([api("/api/catalog"), api("/api/me")]).then(function (res) {
    var cat = res[0] || {};
    S.catalog = cat.tasks || [];
    S.byId = {};
    S.catalog.forEach(function (t) { S.byId[t.id] = t; });
    S.me = res[1] || {};
    renderHeader();
    renderBanner();
    render();
  }).catch(function () {
    $("panel").innerHTML = '<p class="mut">Could not load your progress. Check your connection and refresh.</p>';
  });
})();

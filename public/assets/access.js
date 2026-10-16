/**
 * Dostep do drugiego tieru i potwierdzenie e-mail.
 *
 * Nie udajemy platnosci karta: nie mamy procesora, a falszywy checkout jest
 * gorszy niz brak checkoutu. Zamiast tego prosba o dostep trafia do bazy,
 * admin widzi ja w `admin.py` i nadaje plan, a uzytkownik dostaje potwierdzenie
 * na maila. Miejsce na Stripe jest jedno i nazwane — podmiana to jedna funkcja.
 */
(function () {
  "use strict";

  var esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c];
    });
  };

  function api(path, opts) {
    opts = opts || {};
    return fetch(path, {
      method: opts.method || "GET",
      headers: { "content-type": "application/json" },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      credentials: "same-origin",
    }).then(function (r) { return r.json().catch(function () { return {}; }); });
  }

  function close() {
    var d = document.getElementById("dlg-access");
    if (d) { d.close(); d.remove(); }
  }

  window.openAccessDialog = function () {
    var old = document.getElementById("dlg-access");
    if (old) old.remove();
    var d = document.createElement("dialog");
    d.id = "dlg-access";
    d.innerHTML =
      '<form method="dialog" class="dlg" id="f">' +
      '<h2>Request the second tier</h2>' +
      '<p class="sub">One payment, not a subscription. Tell us who you are and what you want to work on — the scope decides the number, and we reply with it.</p>' +
      '<div class="field"><label for="a-handle">Nickname</label>' +
      '<input id="a-handle" autocomplete="username" placeholder="your Anvil nickname, or leave blank"></div>' +
      '<div class="field"><label for="a-email">E-mail</label>' +
      '<input id="a-email" type="email" autocomplete="email" placeholder="where we should answer"></div>' +
      '<div class="field"><label for="a-why">What do you want to work on?</label>' +
      '<textarea id="a-why" rows="4" placeholder="e.g. red team prep, teaching a group of eight, getting better at eBPF"></textarea></div>' +
      '<div class="err" id="a-err"></div>' +
      '<div class="foot"><button class="btn btn-primary" id="a-go" value="send">Send the request</button>' +
      '<button class="btn btn-ghost" value="cancel">Cancel</button></div>' +
      '<p class="note">No checkout session, no card form, no newsletter. One request, one reply.</p>' +
      "</form>";
    document.body.appendChild(d);
    d.showModal();
    d.addEventListener("close", function () { if (d.returnValue === "send") send(d); else d.remove(); });
  };

  function send(d) {
    var email = d.querySelector("#a-email").value.trim();
    var why = d.querySelector("#a-why").value.trim();
    var err = d.querySelector("#a-err");
    if (!/^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(email)) {
      err.textContent = "Give an e-mail address we can answer to.";
      d.showModal();
      d.returnValue = "again";
      return;
    }
    d.remove();
    api("/api/access/request", {
      method: "POST",
      body: { handle: d.querySelector("#a-handle").value.trim().toLowerCase(), email: email, why: why },
    }).then(function (r) {
      var banner = document.getElementById("banner-slot");
      var text = r.error
        ? r.error
        : "Request received. We answer to " + esc(email) + " — usually within a working day.";
      banner.innerHTML = '<div class="banner info">' + text + "</div>";
    });
  }

  /* ------------------------------------------------------- potwierdzenie e-mail
     Link z maila prowadzi tu, a nie do surowego JSON-a. */
  function verify() {
    var token = new URLSearchParams(location.search).get("token") || "";
    var box = document.getElementById("v");
    if (!box) return;
    if (!/^[0-9a-f]{48}$/.test(token)) {
      box.innerHTML = '<div class="mark no">!</div><h1>This link is not valid</h1>'
        + '<p>Confirmation links look like a single long string and work once. If this one came from '
        + "an older mail, ask for a new one from the panel.</p>"
        + '<p style="margin-top:20px"><a class="btn btn-ghost" href="/panel">Go to your progress</a></p>';
      return;
    }
    box.innerHTML = '<div class="vpage"><p>Confirming…</p></div>';
    api("/api/auth/verify?token=" + encodeURIComponent(token)).then(function (r) {
      if (r.ok) {
        box.innerHTML = '<div class="mark ok">✓</div><h1>E-mail confirmed</h1>'
          + "<p>Your account can be recovered by mail from now on, and your progress follows you to "
          + "any device. Nothing else about you changes — no newsletter, no telemetry.</p>"
          + '<p style="margin-top:22px"><a class="btn btn-primary" href="/lab">Back to the labs</a></p>';
      } else {
        box.innerHTML = '<div class="mark no">!</div><h1>This link no longer works</h1>'
          + "<p>" + esc(r.error || "The link expired or was already used.") + " Confirmation links "
          + "last 24 hours and work once. You can ask for another from the panel.</p>"
          + '<p style="margin-top:22px"><a class="btn btn-ghost" href="/panel">Ask for a new link</a></p>';
      }
    }).catch(function () {
      box.innerHTML = '<div class="mark no">!</div><h1>Network trouble</h1>'
        + "<p>The confirmation did not go through. Check your connection and try the link again.</p>";
    });
  }

  if (document.getElementById("v")) verify();
})();

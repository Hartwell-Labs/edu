#!/usr/bin/env python3
"""
admin.py — zarządzanie kontami Anvil (Cloudflare D1).

  python3 admin.py list
  python3 admin.py create Kija --email kija@hartwell-labs.pl --password '...' --plan lifetime
  python3 admin.py grant Kija lifetime
  python3 admin.py revoke Kija
  python3 admin.py verify Kija            # ręczne potwierdzenie e-mail
  python3 admin.py sendverify Kija        # wyślij link potwierdzający ponownie
  python3 admin.py progress Kija          # co rozwiązał

Wymaga tokenu Cloudflare w ~/.config/hartwell/cf_bot_token.txt (CLOUDFLARE_API_TOKEN)
albo w środowisku. Konto zakładane z poziomu admina jest od razu zweryfikowane —
potwierdzenie e-mail dotyczy kont zakładanych przez UI.
"""
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import subprocess
import sys
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent
ENV = dict(os.environ)
ENV.setdefault("CLOUDFLARE_API_TOKEN",
               (pathlib.Path.home() / ".config/hartwell/cf_bot_token.txt").read_text().strip())
ENV.setdefault("CLOUDFLARE_ACCOUNT_ID", "29ee063c29d9e8f27a8863fadcaa9073")


def sql(query: str) -> str:
    p = subprocess.run(["npx", "wrangler", "d1", "execute", "anvil", "--remote",
                        "--command", query, "--json"],
                       cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=180)
    if p.returncode != 0:
        print(p.stderr.strip()[-500:], file=sys.stderr)
        raise SystemExit(1)
    try:
        data = json.loads(p.stdout)
    except Exception:
        data = []
    rows = []
    for chunk in data if isinstance(data, list) else [data]:
        rows += chunk.get("results", []) or []
    return rows


def derive(password: str, handle: str) -> str:
    """Tak samo jak przeglądarka: PBKDF2-SHA256, 210k, sól 'anvil:<handle>'."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(),
                               f"anvil:{handle.lower()}".encode(), 210_000).hex()


def escape(v: str) -> str:
    return v.replace("'", "''")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list")

    c = sub.add_parser("create")
    c.add_argument("handle")
    c.add_argument("--email", required=True)
    c.add_argument("--password", required=True)
    c.add_argument("--plan", default="free", choices=["free", "lifetime"])

    g = sub.add_parser("grant")
    g.add_argument("handle")
    g.add_argument("plan", choices=["free", "lifetime"])

    rv = sub.add_parser("revoke")
    rv.add_argument("handle")

    v = sub.add_parser("verify")
    v.add_argument("handle")

    sv = sub.add_parser("sendverify")
    sv.add_argument("handle")

    pr = sub.add_parser("progress")
    pr.add_argument("handle")

    args = ap.parse_args()

    if args.cmd == "list":
        for r in sql("SELECT handle, email, plan, email_verified, created_at FROM users ORDER BY created_at"):
            when = time.strftime("%Y-%m-%d", time.localtime(r["created_at"] / 1000))
            print(f"  {r['handle']:16} {r['email']:32} plan={r['plan']:9} "
                  f"mail={'tak' if r['email_verified'] else 'nie'}  {when}")
        return

    if args.cmd == "create":
        h = args.handle.lower()
        v = derive(args.password, h)
        uid = str(uuid.uuid4()); t = int(time.time() * 1000)
        sql(f"INSERT INTO users (id, handle, email, pw_salt, pw_hash, created_at, last_seen, "
            f"plan, email_verified, verify_sent_at) VALUES "
            f"('{uid}', '{escape(h)}', '{escape(args.email.lower())}', 'admin', "
            f"'pbkdf2-sha256$210000${v}', {t}, {t}, '{args.plan}', 1, 0)")
        print(f"  utworzono {h} ({args.plan}), e-mail {args.email}")
        return

    if args.cmd in ("grant", "revoke", "verify"):
        plan = {"grant": args.plan, "revoke": "free", "verify": None}[args.cmd]
        if args.cmd == "verify":
            sql(f"UPDATE users SET email_verified = 1, verify_token = NULL "
                f"WHERE handle = '{escape(args.handle.lower())}'")
            print(f"  {args.handle}: e-mail potwierdzony ręcznie")
        else:
            sql(f"UPDATE users SET plan = '{plan}' WHERE handle = '{escape(args.handle.lower())}'")
            print(f"  {args.handle}: plan = {plan}")
        return

    if args.cmd == "sendverify":
        import urllib.request
        rows = sql(f"SELECT id, handle, email FROM users WHERE handle = '{escape(args.handle.lower())}'")
        if not rows:
            print("  brak konta"); return
        u = rows[0]
        token = secrets.token_hex(24)
        sql(f"UPDATE users SET verify_token = '{token}', verify_sent_at = {int(time.time()*1000)}, "
            f"email_verified = 0 WHERE id = '{u['id']}'")
        key = "".join((pathlib.Path.home() / ".config/hartwell/resend_api_key.txt").read_text().split())
        link = f"https://edu.hartwell-labs.pl/api/auth/verify?token={token}"
        body = (f"Hi {u['handle']},\n\nConfirm your e-mail in Anvil — open the link:\n\n{link}\n\n"
                f"The link is valid for 24 hours. If you did not sign up, ignore this message.\n\n— Anvil")
        req = urllib.request.Request(
            "https://api.resend.com/emails", method="POST",
            data=json.dumps({"from": "Anvil <labs@hartwell-labs.pl>", "to": [u["email"]],
                             "subject": "Confirm your e-mail in Anvil", "text": body}).encode(),
            headers={"Authorization": f"Bearer {key}", "content-type": "application/json",
                     "User-Agent": "curl/8.0 anvil-admin"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                print(f"  wysłano na {u['email']} (HTTP {r.status})")
        except Exception as e:
            print(f"  BŁĄD wysyłki: {e}")
        print(f"  link: {link}")
        return

    if args.cmd == "progress":
        uid = sql(f"SELECT id FROM users WHERE handle = '{escape(args.handle.lower())}'")
        if not uid:
            print("  brak konta"); return
        rows = sql(f"SELECT task_id, passed, points, attempts, hints_used FROM progress "
                   f"WHERE user_id = '{uid[0]['id']}' ORDER BY passed DESC, points DESC")
        done = [r for r in rows if r["passed"]]
        pts = sum(r["points"] or 0 for r in done)
        print(f"  {args.handle}: {len(done)}/{len(rows)} rozwiązanych, {pts} pkt")
        for r in rows:
            mark = "✓" if r["passed"] else "·"
            print(f"    {mark} {r['task_id']:24} {r['points'] or 0:>4} pkt  "
                  f"próby={r['attempts']} podpowiedzi={r['hints_used']}")


if __name__ == "__main__":
    main()
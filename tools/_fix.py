import pathlib

p = pathlib.Path("tools/specs_logs2.py")
s = p.read_text()

# (id, stare pola, nowe pola, poprawiony podpowiedni-opcjonalnie)
FIX = [
    ("log2-nginx-upstream", [("ip", 0), ("status", 7), ("upstream", 11)],
     [("ip", 0), ("status", 8), ("upstream", 12)],
     "The upstream address and its status come after the quoted agent, not in the request half."),
    ("log2-slow-query", [("level", 3), ("ms", 5), ("user", 7), ("sql", 9)],
     [("level", 2), ("ms", 5), ("user", 6), ("sql", 7)],
     "Everything from the level on is `key=value` except the SQL, which is the tail of the line."),
    ("log2-wireguard", [("interface", 0), ("tries", 9), ("last_try", 12)],
     [("interface", 0), ("tries", 12), ("last_try", 17)],
     "The interface name sits in front of the colon and keeps the colon."),
    ("log2-cloudfront", [("ip", 1), ("host", 3), ("status", 7), ("time", 15)],
     [("ip", 2), ("host", 4), ("status", 6), ("time", 10)],
     "The date is two fields, so the address is the third and the status the seventh."),
    ("log2-okta", [("app", 1), ("event", 3), ("user", 5), ("result", 9)],
     [("app", 1), ("event", 2), ("user", 3), ("result", 5)],
     "One `key=value` per field after the timestamp; the result is the last one."),
    ("log2-sudo", [("user", 10), ("tty", 13), ("rhost", 15)],
     [("user", 14), ("tty", 11), ("rhost", 13)],
     "`pam_unix(sudo:auth):` is one field, but the message after it is split on every space."),
    ("log2-ufw", [("in", 4), ("src", 6), ("dpt", 10)],
     [("in", 7), ("src", 9), ("dpt", 13)],
     "`[UFW` and `BLOCK]` are two fields — the bracket is not quoting anything."),
    ("log2-vault-audit", [("type", 2), ("time", 3), ("secret", 5), ("user", 8)],
     [("type", 2), ("time", 3), ("secret", 4), ("user", 5)],
     "After `type=` and `time=` the path is a bare field; the display name is the last one."),
    ("log2-bpf", [("offset", 1), ("pid", 2), ("uid", 4), ("path", 7)],
     [("offset", 1), ("pid", 2), ("uid", 3), ("path", 5)],
     "The `+0x1c/0x40` part is one field, and the path is the last one."),
    ("log2-git-fetch", [("user", 2), ("command", 6), ("result", 12)],
     [("user", 2), ("command", 4), ("result", 14)],
     "The user and the command are fixed positions; the result is the tail of the line."),
    ("log2-tls-alert", [("peer", 2), ("reason", 3), ("alert", 5), ("version", 7)],
     [("peer", 3), ("reason", 4), ("alert", 5), ("version", 6)],
     "Every field is `key=value`, and the date and time are two of them."),
    ("log2-saml", [("idp", 2), ("user", 4), ("binding", 6), ("status", 8)],
     [("idp", 3), ("user", 4), ("binding", 5), ("status", 6)],
     "Single-letter keys, so the values are the fields that matter."),
    ("log2-scheduler", [("job", 3), ("shard", 5), ("queue", 7)],
     [("job", 4), ("shard", 5), ("queue", 6)],
     "Level, then the component, then `key=value` pairs; the queue is the last pair."),
    ("log2-nginx-error", [("level", 2), ("path", 4), ("client", 11)],
     [("level", 2), ("path", 6), ("client", 15)],
     "The path is inside the message, not a standalone field — count past the `*n` and `open()`."),
    ("log2-fail2ban-found", [("action", 3), ("ip", 6), ("count", 8)],
     [("action", 4), ("ip", 7), ("count", 9)],
     "The address is the third-from-last field and the count the second-from-last."),
    ("log2-envoy-tls", [("method", 1), ("status", 2), ("duration", 10), ("sni", 15), ("cipher", 17)],
     [("method", 1), ("status", 4), ("duration", 9), ("sni", 13), ("cipher", 14)],
     "The SNI and the negotiated cipher are the last two quoted fields."),
    ("log2-iptables-drop", [("in", 0), ("src", 5), ("dpt", 9), ("deny_dpt", 17)],
     [("in", 0), ("src", 3), ("dpt", 7), ("deny_dpt", 11)],
     "The `MAC=` field is what pushes the later pairs along by one, and `DENY` by two."),
    ("log2-gitlab", [("user", 2), ("action", 4), ("project", 6), ("target", 8)],
     [("user", 3), ("action", 4), ("project", 5), ("target", 6)],
     "The prefix ends with a colon and counts as one field, and the date is two."),
    ("log2-podman", [("level", 4), ("file", 5), ("line", 6), ("address", 11)],
     [("level", 4), ("program", 5), ("location", 6), ("address", 10)],
     "`main.go:231:` is one field, line number included."),
    ("log2-sentry", [("event", 1), ("logger", 3), ("transaction", 5), ("release", 7), ("culprit", 9)],
     [("event", 2), ("logger", 4), ("transaction", 5), ("release", 6), ("culprit", 7)],
     "The date is two fields; everything from the third on is `key=value`."),
    ("log2-nftables", [("in", 2), ("src", 5), ("dpt", 10)],
     [("in", 2), ("src", 4), ("dpt", 9)],
     "`kernel:` and `nftables:` are two fields before the chain starts."),
    ("log2-tailscale", [("component", 2), ("peer", 4), ("endpoint", 6)],
     [("component", 1), ("peer", 3), ("endpoint", 4)],
     "The `disco:` prefix is a field of its own, and the timestamp is the tail."),
    ("log2-postgres", [("pid", 2), ("level", 3), ("sql", 6)],
     [("pid", 3), ("level", 4), ("sql", 6)],
     "`UTC` and the bracketed pid are separate fields, and the SQL starts after `statement:`."),
]

changed = 0
for tid, old, new, hint in FIX:
    old_s = "[" + ", ".join(f'("{k}", {i})' for k, i in old) + "]"
    new_s = "[" + ", ".join(f'("{k}", {i})' for k, i in new) + "]"
    assert s.count(old_s) == 1, f"{tid}: {old_s}"
    s = s.replace(old_s, new_s)
    changed += 1

# docker json nie dzieli sie na tokeny — zamieniam na syslog, ktory sie dzieli
old_docker = '''    ("log2-docker-json", "Parse a Docker json-file log line",
     '{"time":"2026-10-16T09:12:44Z","stream":"stdout","log":"worker started port=8080"}',
     [("stream", 1), ("log", 2)], "Docker json-file",
     "The whole message is JSON: the `log` value is where the text log lives."),'''
new_docker = '''    ("log2-syslog", "Parse a syslog line with a PID",
     "Sep 16 09:12:44 lab anvil-lab[2311]: listening on 0.0.0.0:8080",
     [("host", 3), ("unit", 4), ("message", 5), ("address", 7)], "syslog",
     "The PID is glued to the unit name, so the address is the last field and the PID has to be split out."),'''
assert s.count(old_docker) == 1
s = s.replace(old_docker, new_docker)
p.write_text(s)
print(f"specs_logs2.py: {changed} pozycji z poprawnymi indeksami + syslog zamiast json")

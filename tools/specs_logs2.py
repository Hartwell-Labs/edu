#!/usr/bin/env python3
"""specs_logs2.py — kolejne formaty logow i agregacje (Python w Pyodide)."""
from gen_tasks import parse_log, task, tests

LOGS2 = [
    ("log2-nginx-upstream", "Parse an nginx line with an upstream status",
     '10.0.0.7 - - [16/Oct/2026:09:12:44 +0000] "GET /api HTTP/1.1" 502 0 "-" "anvil-cli" 10.0.0.9:8080 "bad gateway" 0.031 502',
     [("ip", 0), ("status", 8), ("upstream", 12)], "nginx with an upstream",
     "The upstream address and its status come after the quoted agent, not in the request half."),

    ("log2-slow-query", "Parse a slow-query log line",
     "2026-10-16 09:12:44 [WARN] query took 2311ms user=kija sql=SELECT * FROM users WHERE id=1",
     [("level", 2), ("ms", 5), ("user", 6), ("sql", 7)], "database slow query",
     "Everything after the level is `key=value`; the SQL is the last field, spaces and all."),

    ("log2-wireguard", "Parse a WireGuard handshake line",
     "anvil0: Handshake did not complete after 5 seconds, we tried to send 1 times, last try at 1792080877",
     [("interface", 0), ("tries", 12), ("last_try", 17)], "WireGuard",
     "The interface name sits in front of the colon and keeps the colon."),

    ("log2-cloudfront", "Parse a CloudFront line",
     '2026-10-16 09:12:44 10.0.0.7 - lab-a.example.com 3/4YjH2k0A1bCdEfGhIjKlMnOpQrStUvWxYz 200 1024 "-" "anvil-cli" 0.031 2311 443 203.0.113.9 TLSv1.3 ECDHE-RSA-AES128-GCM-SHA256',
     [("ip", 2), ("host", 4), ("status", 6), ("time", 10)], "CloudFront",
     "The date is two fields, so everything after the address shifts by one."),

    ("log2-okta", "Parse an Okta system log line",
     "2026-10-16T09:12:44Z app=myapp event=app.session.start user=kija id=abc123 result=SUCCESS",
     [("app", 1), ("event", 2), ("user", 3), ("result", 5)], "Okta",
     "One `key=value` per field after the timestamp; the result is the last one."),

    ("log2-sudo", "Parse a sudo authentication failure",
     "Sep 16 09:12:44 lab sudo: pam_unix(sudo:auth): authentication failure; logname=kija uid=1000 euid=0 tty=/dev/pts/0 ruser=lab rhost= user=kija",
     [("user", 14), ("tty", 11), ("rhost", 13)], "sudo",
     "`pam_unix(sudo:auth)` counts as one field, which shifts everything after it by one."),

    ("log2-ufw", "Parse a UFW block line",
     "Oct 16 09:12:44 lab kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.7 DST=192.168.1.1 PROTO=TCP SPT=51234 DPT=22",
     [("in", 7), ("src", 9), ("dpt", 13)], "UFW",
     "`[UFW BLOCK]` is one field; every interface and address is a `KEY=VALUE` pair."),

    ("log2-vault-audit", "Parse a Vault audit device line",
     "2026-10-16T09:12:44.123Z audit type=response time=3ms secret/anvil/data/password auth.token.displayname=kija",
     [("type", 2), ("time", 3), ("secret", 4), ("user", 5)], "HashiCorp Vault",
     "The path is a bare field; the display name is the last `key=`, and its value is a dotted key."),

    ("log2-bpf", "Parse an eBPF trace line",
     "12.345: bpf_probe_read_user+0x1c/0x40 pid=2311 uid=1000 ret=-14 path=/home/kija/.ssh/id_rsa",
     [("offset", 1), ("pid", 2), ("uid", 3), ("path", 5)], "eBPF verifier trace",
     "The `+0x1c/0x40` part is one field; the path is the last one."),

    ("log2-syslog", "Parse a syslog line with a PID",
     "Sep 16 09:12:44 lab anvil-lab[2311]: listening on 0.0.0.0:8080",
     [("host", 3), ("unit", 4), ("message", 5), ("address", 7)], "syslog",
     "The PID is glued to the unit name, so the address is the last field and the PID has to be split out."),

    ("log2-git-fetch", "Parse a git fetch line",
     "2026-10-16 09:12:44 kija@lab anvil$ git fetch origin 2>&1: From github.com:Hartwell-Labs/edu * branch main -> FETCH_HEAD 1 file changed",
     [("user", 2), ("command", 4), ("result", 14)], "git",
     "The user and the command are fixed positions; the result is the tail of the line."),

    ("log2-tls-alert", "Parse a TLS alert",
     "2026-10-16 09:12:44 tls-alert peer=203.0.113.9:443 reason=bad_certificate alert=42 version=TLSv1.2",
     [("peer", 3), ("reason", 4), ("alert", 5), ("version", 6)], "TLS alert",
     "Every field is `key=value`; the description may contain spaces, so the pairs are the reliable part."),

    ("log2-saml", "Parse a SAML response audit line",
     "2026-10-16 09:12:44 saml idp=hartwell user=kija binding=redirect status=success session=9f2c1a",
     [("idp", 3), ("user", 4), ("binding", 5), ("status", 6)], "SAML",
     "Single-letter keys, so the values are the fields that matter."),

    ("log2-k8s", "Parse a Kubernetes event line",
     '2026-10-16 09:12:44 event Normal Scheduled pod/anvil-7c9d Successfully assigned anvil-7c9d to lab-node-2',
     [("kind", 2), ("reason", 3), ("object", 4), ("node", 8)], "Kubernetes",
     "`pod/anvil-7c9d` is one field; the node is the last one."),

    ("log2-nginx-error", "Parse an nginx error log line",
     "2026/10/16 09:12:44 [error] 2311#2311: *1 open() /srv/www/secret failed (2: No such file or directory), client: 10.0.0.7",
     [("level", 2), ("path", 6), ("client", 15)], "nginx error",
     "The path is inside the message, not a standalone field — count past the `#pid` pair."),

    ("log2-fail2ban-found", "Parse a fail2ban detection line",
     "2026-10-16 09:12:44,123 fail2ban.actions [2311]: NOTICE [sshd] Found 203.0.113.9 - 3 times",
     [("action", 4), ("ip", 7), ("count", 9)], "fail2ban detection",
     "The address is the second-to-last field and the count is the last one."),

    ("log2-scheduler", "Parse a cron scheduler line",
     "2026-10-16T09:12:44Z INFO scheduler dispatch job=nightly-backup shard=3 queue=default",
     [("job", 4), ("shard", 5), ("queue", 6)], "job scheduler",
     "Level, then `key=value` pairs; the queue is the last pair."),

    ("log2-envoy-tls", "Parse an Envoy connection log line",
     '[2026-10-16T09:12:44.123Z] "GET /api HTTP/1.1" 200 - via_upstream - "-" 2311 31 3 4 "lab.example.com" "ECDHE-RSA-AES128-GCM-SHA256"',
     [("method", 1), ("status", 4), ("duration", 9), ("sni", 13), ("cipher", 14)], "Envoy connection",
     "The SNI and the negotiated cipher are the last two quoted fields."),

    ("log2-iptables-drop", "Parse an iptables drop with a reason",
     "IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=10.0.0.7 DST=10.0.0.1 PROTO=TCP SPT=51234 DPT=23 DENY proto=tcp spt=51234 dpt=23",
     [("in", 0), ("src", 3), ("dpt", 7), ("deny_dpt", 11)], "netfilter",
     "The `MAC=` field is what pushes the later pairs along by one."),

    ("log2-gitlab", "Parse a GitLab audit line",
     "2026-10-16 09:12:44 gitlab-rails: user_id=42 action=project.update project_id=7 target_name=anvil",
     [("user", 3), ("action", 4), ("project", 5), ("target", 6)], "GitLab",
     "The prefix ends with a colon and counts as one field."),

    ("log2-podman", "Parse a Podman log line",
     "2026-10-16 09:12:44.000 +0000 UTC FATA[0000] anvil-lab main.go:231: failed to bind :8080 address already in use",
     [("level", 4), ("program", 5), ("location", 6), ("address", 10)], "Podman",
     "`main.go:231:` is one field; the address is the second-to-last."),

    ("log2-sentry", "Parse a Sentry event line",
     "2026-10-16 09:12:44 event=error level=error logger=api.orders transaction=t-9911 release=1.4.2 culprit=app/views/orders.py",
     [("event", 2), ("logger", 4), ("transaction", 5), ("release", 6), ("culprit", 7)], "Sentry",
     "The level is the second `key=value`; the culprit is the last."),

    ("log2-nftables", "Parse an nftables log line",
     "kernel: nftables: IN=eth0 MAC=aa:bb:cc:dd:ee:ff SRC=203.0.113.9 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=41234 DPT=22",
     [("in", 2), ("src", 4), ("dpt", 9)], "nftables",
     "`nftables:` is its own field, so the chain starts one position later than in UFW."),

    ("log2-tailscale", "Parse a Tailscale log line",
     "tailscaled: magicsock: disco: peer=kija-laptop endpoint=203.0.113.9:41641 discovered at 2026-10-16T09:12:44Z",
     [("component", 1), ("peer", 3), ("endpoint", 4)], "Tailscale",
     "The `disco:` prefix is a field of its own, and the timestamp is the tail."),

    ("log2-postgres", "Parse a PostgreSQL log line",
     "2026-10-16 09:12:44 UTC [1234] LOG:  statement: SELECT * FROM sessions WHERE token = 'abc'",
     [("pid", 3), ("level", 4), ("sql", 6)], "PostgreSQL",
     "The `UTC` token and the bracketed pid are separate fields, and the SQL is the tail."),
]

LOG2_TASKS = [parse_log(tid, title, sample, fields, area=area, hint=hint)
              for tid, title, sample, fields, area, hint in LOGS2]


# ---------------------------------------------------------------- agregacje
# (id, tytul, trudnosc, punkty, opis, setup, rozwiazanie, testy, podpowiedzi, starter)
AGG2 = [
    ("agg2-status-by-hour", "Group requests by hour and status", 3, 170,
     "One request per line: `hour status path`. Complete `by_hour` so it returns a dict of "
     "`(hour, status) -> count`, skipping lines that do not have three fields. That is the "
     "first query you write when a service starts returning 500s somewhere in the afternoon.\n\n"
     "**Stretch:** return only the hours whose 5xx count grew compared to the previous hour.",
     "LOG = '''09 200 /a\n09 500 /b\n09 200 /c\n10 500 /d\n10 200 /e\nbroken line\n'''\n",
     "def by_hour(lines):\n"
     "    out = {}\n"
     "    for line in lines:\n"
     "        p = line.split()\n"
     "        if len(p) != 3:\n"
     "            continue\n"
     "        key = (p[0], p[1])\n"
     "        out[key] = out.get(key, 0) + 1\n"
     "    return out\n",
     [("the 200s at 09", "by_hour(LOG.splitlines())[('09', '200')] == 2", "by_hour(LOG.splitlines())"),
      ("the 500s at 10", "by_hour(LOG.splitlines())[('10', '500')] == 1", "by_hour(LOG.splitlines())"),
      ("broken line skipped", "sum(by_hour(LOG.splitlines()).values()) == 5", "total counted requests"),
      ("empty log", "by_hour([]) == {}", "by_hour([])")],
     ["A tuple key works in a dict exactly like a string one.",
      "Count with `out[key] = out.get(key, 0) + 1` — `Counter` does the same in one line."],
     "def by_hour(lines):\n    ...\n"),

    ("agg2-first-seen", "Order addresses by when they first appeared", 3, 160,
     "Complete `first_seen` so it returns the addresses sorted by their **first** appearance, "
     "each with the index of that first sighting. Sorted output makes a diff between two logs "
     "readable — new scanners show up at the top.\n\n"
     "**Stretch:** return only the addresses that did not appear in a second log.",
     "LOG = ['10.0.0.1', '10.0.0.2', '10.0.0.1', '10.0.0.3', '10.0.0.2']\n",
     "def first_seen(lines):\n"
     "    seen = {}\n"
     "    for i, ip in enumerate(lines):\n"
     "        if ip not in seen:\n"
     "            seen[ip] = i\n"
     "    return sorted(seen.items(), key=lambda kv: kv[1])\n",
     [("order of first appearance", "[ip for ip, _ in first_seen(LOG)] == ['10.0.0.1', '10.0.0.2', '10.0.0.3']", "first_seen(LOG)"),
      ("index is kept", "first_seen(LOG)[0] == ('10.0.0.1', 0)", "first_seen(LOG)[0]"),
      ("empty", "first_seen([]) == []", "first_seen([])"),
      ("repeats do not move", "[ip for ip, _ in first_seen(['a', 'b', 'a'])] == ['a', 'b']", "first_seen(['a', 'b', 'a'])")],
     ["Record the index only the first time you see a value — `if ip not in seen`.",
      "`sorted(d.items(), key=...)` sorts by value; a plain `sorted(d.items())` compares the tuples."],
     "def first_seen(lines):\n    ...\n"),

    ("agg2-singletons", "Find lines that appear exactly once", 3, 150,
     "Complete `singletons` so it returns the lines occurring exactly once, in first-appearance "
     "order. A line that appears once in a million is usually the interesting one.\n\n"
     "**Stretch:** ignore lines shorter than ten characters.",
     "LOG = ['GET /', '404', 'GET /', 'a-very-long-unique-line', '404', 'GET /health']\n",
     "def singletons(lines):\n"
     "    counts = {}\n"
     "    for line in lines:\n"
     "        counts[line] = counts.get(line, 0) + 1\n"
     "    out, seen = [], set()\n"
     "    for line in lines:\n"
     "        if counts[line] == 1 and line not in seen:\n"
     "            seen.add(line)\n"
     "            out.append(line)\n"
     "    return out\n",
     [("the unique long line", "singletons(LOG) == ['a-very-long-unique-line', 'GET /health']", "singletons(LOG)"),
      ("the repeated 404 is out", "'404' not in singletons(LOG)", "singletons(LOG)"),
      ("empty", "singletons([]) == []", "singletons([])"),
      ("everything unique", "singletons(['a', 'b']) == ['a', 'b']", "singletons(['a', 'b'])")],
     ["Count first, then walk the list again — that is what keeps the original order.",
      "A set of already-emitted lines stops a singleton being added twice."],
     "def singletons(lines):\n    ...\n"),

    ("agg2-sessions", "Group requests into sessions by a gap", 3, 210,
     "Complete `sessions` so it groups `(ip, minute)` pairs into sessions: a gap of more than "
     "`gap` minutes starts a new session, and a new address always does. Sessionisation is the "
     "first thing you do before talking about \"a user\".\n\n"
     "**Stretch:** return the sessions themselves, not just the count.",
     "LOG = [('10.0.0.1', 0), ('10.0.0.1', 5), ('10.0.0.1', 30), ('10.0.0.2', 31)]\n",
     "def sessions(events, gap):\n"
     "    last = {}\n"
     "    count = 0\n"
     "    for ip, minute in events:\n"
     "        if ip not in last or minute - last[ip] > gap:\n"
     "            count += 1\n"
     "        last[ip] = minute\n"
     "    return count\n",
     [("one gap starts a session", "sessions(LOG, 10) == 3", "sessions(LOG, 10)"),
      ("a generous gap merges them", "sessions(LOG, 60) == 2", "sessions(LOG, 60)"),
      ("empty", "sessions([], 10) == 0", "sessions([], 10)"),
      ("single event", "sessions([('a', 0)], 10) == 1", "sessions([('a', 0)], 10)"),
      ("same minute is one session", "sessions([('a', 0), ('a', 0)], 10) == 1", "sessions([('a', 0), ('a', 0)], 10)")],
     ["A dict of address → last minute seen is all the state you need.",
      "A new address is always a new session, whatever the gap is."],
     "def sessions(events, gap):\n    ...\n"),

    ("agg2-agents", "Count user agents and name the odd ones", 3, 180,
     "Complete `agents` so it returns `(most_common, its_count, others)` where `others` is the "
     "number of distinct remaining agents. One agent at 99% and a handful of others is a scanner, "
     "not a user base.\n\n"
     "**Stretch:** normalise each agent by cutting at the first space before counting.",
     "LOG = ['curl/8.0', 'curl/8.0', 'curl/8.0', 'python-requests/2.31', 'sqlmap/1.7']\n",
     "def agents(lines):\n"
     "    counts = {}\n"
     "    for ua in lines:\n"
     "        counts[ua] = counts.get(ua, 0) + 1\n"
     "    if not counts:\n"
     "        return None, 0, 0\n"
     "    top, n = max(counts.items(), key=lambda kv: kv[1])\n"
     "    return top, n, len(counts) - 1\n",
     [("the top agent", "agents(LOG)[0] == 'curl/8.0'", "agents(LOG)[0]"),
      ("its count", "agents(LOG)[1] == 3", "agents(LOG)[1]"),
      ("two others", "agents(LOG)[2] == 2", "agents(LOG)[2]"),
      ("empty", "agents([]) == (None, 0, 0)", "agents([])"),
      ("one agent only", "agents(['x', 'x'])[2] == 0", "agents(['x', 'x'])")],
     ["`max(counts.items(), key=lambda kv: kv[1])` gives the busiest pair.",
      "An empty dict makes `max()` raise — decide what an empty log returns and return it early."],
     "def agents(lines):\n    ...\n"),

    ("agg2-error-ratio", "Compute an error ratio per endpoint", 3, 190,
     "Complete `error_ratio` so it returns `{path: errors / requests}` for every path, rounded to "
     "three decimals, where errors are 5xx only. An endpoint that fails 100% of the time is a "
     "broken link, not an attack.\n\n"
     "**Stretch:** return `None` for a path with no requests at all.",
     "LOG = '''/login 200\n/login 200\n/login 500\n/admin 200\n/robots 404\n'''\n",
     "def error_ratio(lines):\n"
     "    total, bad = {}, {}\n"
     "    for line in lines:\n"
     "        p = line.split()\n"
     "        if len(p) != 2:\n"
     "            continue\n"
     "        path, status = p\n"
     "        total[path] = total.get(path, 0) + 1\n"
     "        if int(status) >= 500:\n"
     "            bad[path] = bad.get(path, 0) + 1\n"
     "    return {p: round(bad.get(p, 0) / n, 3) for p, n in total.items()}\n",
     [("login", "error_ratio(LOG.splitlines())['/login'] == 0.333", "error_ratio(LOG.splitlines())['/login']"),
      ("admin has none", "error_ratio(LOG.splitlines())['/admin'] == 0.0", "error_ratio(LOG.splitlines())['/admin']"),
      ("a 404 is not a 5xx", "error_ratio(LOG.splitlines())['/robots'] == 0.0", "error_ratio(LOG.splitlines())['/robots']"),
      ("empty", "error_ratio([]) == {}", "error_ratio([])"),
      ("broken line skipped", "error_ratio(['junk']) == {}", "error_ratio(['junk'])")],
     ["Two dicts: total requests and 5xx requests, keyed by path.",
      "`round(x, 3)` gives three decimals; `int(status) >= 500` is the error test."],
     "def error_ratio(lines):\n    ...\n"),

    ("agg2-tail-follow", "Follow a file that keeps growing", 2, 170,
     "Complete `new_lines` so it returns the lines of `content` after the first `seen` ones, plus "
     "the new total. A log tailer is this function in a loop — get the offset arithmetic wrong and "
     "you either duplicate or skip lines forever.\n\n"
     "**Stretch:** treat a file that shrank as rotated, and return everything.",
     "",
     "def new_lines(content, seen):\n"
     "    lines = content.splitlines()\n"
     "    if len(lines) < seen:\n"
     "        return lines, len(lines)\n"
     "    return lines[seen:], len(lines)\n",
     [("first read", "new_lines('a\\nb', 0) == (['a', 'b'], 2)", "new_lines('a\\nb', 0)"),
      ("nothing new", "new_lines('a\\nb', 2) == ([], 2)", "new_lines('a\\nb', 2)"),
      ("one new line", "new_lines('a\\nb\\nc', 2) == (['c'], 3)", "new_lines('a\\nb\\nc', 2)"),
      ("rotated file", "new_lines('x', 5) == (['x'], 1)", "new_lines('x', 5)"),
      ("empty file", "new_lines('', 0) == ([], 0)", "new_lines('', 0)")],
     ["Return a tuple — the new lines and the new total — so the caller can store the total.",
      "A total **smaller** than what you saw means the file was rotated."],
     "def new_lines(content, seen):\n    ...\n"),

    ("agg2-grep-context", "Grep with one line of context", 3, 180,
     "Complete `context` so it returns every line of `text` containing `needle`, with one line "
     "before and one after, without duplicates and in order. This is `grep -C 1`, and it is how "
     "you read an error out of a stack trace.\n\n"
     "**Stretch:** take the number of context lines as an argument.",
     "TEXT = 'line one\\nthe needle\\nline three\\nline four\\nline five'\n",
     "def context(text, needle):\n"
     "    lines = text.splitlines()\n"
     "    keep = set()\n"
     "    for i, line in enumerate(lines):\n"
     "        if needle in line:\n"
     "            for j in (i - 1, i, i + 1):\n"
     "                if 0 <= j < len(lines):\n"
     "                    keep.add(j)\n"
     "    return [line for i, line in enumerate(lines) if i in keep]\n",
     [("needle and its neighbour", "context(TEXT, 'needle') == ['line one', 'the needle', 'line three']", "context(TEXT, 'needle')"),
      ("second needle adds the far side", "context(TEXT, 'line four') == ['line three', 'line four', 'line five']", "context(TEXT, 'line four')"),
      ("nothing found", "context(TEXT, 'zzz') == []", "context(TEXT, 'zzz')"),
      ("empty text", "context('', 'x') == []", "context('', 'x')"),
      ("no duplicates", "context('a\\nx\\na', 'x') == ['a', 'x', 'a']", "context('a\\nx\\na', 'x')")],
     ["Collect the **indexes** you want in a set, then rebuild the list in order.",
      "A set is what stops the shared line between two matches appearing twice."],
     "def context(text, needle):\n    ...\n"),

    ("agg2-cut", "Cut a fixed field out of a table", 2, 110,
     "Complete `cut` so it returns the values of column `n` (zero-based) from lines separated by "
     "`sep`, skipping lines with too few fields. `cut -d, -f2` is the same tool, and the skip is "
     "the part everyone forgets.\n\n"
     "**Stretch:** return `(value, line_number)` pairs.",
     "LOG = 'a,1,x\\nb,2,y\\nc,3,z\\nshort'\n",
     "def cut(text, sep, n):\n"
     "    out = []\n"
     "    for line in text.splitlines():\n"
     "        p = line.split(sep)\n"
     "        if len(p) > n:\n"
     "            out.append(p[n])\n"
     "    return out\n",
     [("second column", "cut(LOG, ',', 1) == ['1', '2', '3']", "cut(LOG, ',', 1)"),
      ("first column", "cut(LOG, ',', 0) == ['a', 'b', 'c', 'short']", "cut(LOG, ',', 0)"),
      ("short line skipped", "cut('a,b', ',', 5) == []", "cut('a,b', ',', 5)"),
      ("empty", "cut('', ',', 0) == []", "cut('', ',', 0)"),
      ("tab separator", "cut('a\\tb', '\\t', 1) == ['b']", "cut('a\\tb', '\\t', 1)")],
     ["`len(p) > n` skips short lines — `>=` would keep a line with exactly n fields.",
      "`split(sep)` with an explicit separator, not `split()`."],
     "def cut(text, sep, n):\n    ...\n"),

    ("agg2-distinct", "Count distinct values, not occurrences", 2, 120,
     "Complete `distinct` so it returns how many different values appear, ignoring case and "
     "surrounding whitespace. A set does the counting; the normalisation is the lesson — ` HTTP ` "
     "and `http` are one client, not two.\n\n"
     "**Stretch:** return the values themselves, sorted.",
     "LOG = ' HTTP \\nhttp\\ncurl\\nCURL\\n'\n",
     "def distinct(lines):\n"
     "    return len({line.strip().lower() for line in lines if line.strip()})\n",
     [("HTTP and curl are two clients, not four", "distinct(LOG.splitlines()) == 2", "distinct(LOG.splitlines())"),
      ("blank lines ignored", "distinct(['', '  ']) == 0", "distinct(['', '  '])"),
      ("no duplicates", "distinct(['a', 'a', 'a']) == 1", "distinct(['a', 'a', 'a'])"),
      ("empty", "distinct([]) == 0", "distinct([])"),
      ("case only", "distinct(['X', 'x']) == 1", "distinct(['X', 'x'])")],
     ["A set comprehension over `line.strip().lower()` does the whole thing.",
      "Filter the empty string out **before** the set, or `''` counts as a value."],
     "def distinct(lines):\n    ...\n"),

    ("agg2-buckets", "Bucket timestamps into minutes", 3, 170,
     "Complete `buckets` so it returns `minute -> count` for integer minute numbers, with absent "
     "minutes missing rather than zero. Continuous counters are how a graph gets the wrong shape "
     "after a quiet hour.\n\n"
     "**Stretch:** return the series filled with zeroes so a graph shows the gap.",
     "STAMPS = [0, 0, 3, 61, 62, 900]\n",
     "def buckets(stamps):\n"
     "    out = {}\n"
     "    for t in stamps:\n"
     "        m = t // 60\n"
     "        out[m] = out.get(m, 0) + 1\n"
     "    return out\n",
     [("first minute", "buckets(STAMPS)[0] == 3", "buckets(STAMPS)"),
      ("minute one", "buckets(STAMPS)[1] == 2", "buckets(STAMPS)"),
      ("minute fifteen", "buckets(STAMPS)[15] == 1", "buckets(STAMPS)"),
      ("absent minutes", "2 not in buckets(STAMPS)", "buckets(STAMPS)"),
      ("empty", "buckets([]) == {}", "buckets([])")],
     ["Integer division `//` is the bucket; a float would create a bucket per value.",
      "Only keys you actually saw exist — `in` distinguishes absent from zero."],
     "def buckets(stamps):\n    ...\n"),

    ("agg2-collapse", "Collapse a repeated alert flood", 3, 200,
     "Complete `collapse` so a message identical to the previous one is reported once, with a "
     "repeat count and the last timestamp. A misconfigured service logs the same error ten "
     "thousand times and the count is the actual story.\n\n"
     "**Stretch:** collapse runs shorter than `gap` seconds apart as well.",
     "LOG = [('a', 0), ('a', 1), ('b', 2), ('a', 9)]\n",
     "def collapse(events):\n"
     "    out = []\n"
     "    for msg, t in events:\n"
     "        if out and out[-1][0] == msg:\n"
     "            out[-1] = (msg, out[-1][1] + 1, t)\n"
     "        else:\n"
     "            out.append((msg, 1, t))\n"
     "    return out\n",
     [("the run collapses", "collapse(LOG)[0] == ('a', 2, 1)", "collapse(LOG)[0]"),
      ("a different message starts a new entry", "collapse(LOG)[1] == ('b', 1, 2)", "collapse(LOG)[1]"),
      ("the later a is its own", "collapse(LOG)[2] == ('a', 1, 9)", "collapse(LOG)[2]"),
      ("empty", "collapse([]) == []", "collapse([])"),
      ("no repeats", "collapse([('x', 0), ('y', 1)]) == [('x', 1, 0), ('y', 1, 1)]", "collapse([('x', 0), ('y', 1)])")],
     ["A list works as a stack here: look at `out[-1]`, and replace it to bump the count.",
      "Compare with the **last** entry, not with every one — otherwise equal lines that are not adjacent merge."],
     "def collapse(events):\n    ...\n"),

    ("agg2-share", "Share of traffic per path", 2, 140,
     "Complete `share` so it returns `{path: count / total}` for each path, and `{}` for an empty "
     "log. A path at 98% of traffic is a load-balancer problem waiting to happen.\n\n"
     "**Stretch:** return the shares as whole-number percentages.",
     "LOG = ['/a', '/a', '/a', '/b']\n",
     "def share(lines):\n"
     "    counts = {}\n"
     "    for line in lines:\n"
     "        line = line.strip()\n"
     "        if line:\n"
     "            counts[line] = counts.get(line, 0) + 1\n"
     "    total = sum(counts.values())\n"
     "    if not total:\n"
     "        return {}\n"
     "    return {p: c / total for p, c in counts.items()}\n",
     [("three quarters", "share(LOG)['/a'] == 0.75", "share(LOG)['/a']"),
      ("the rest", "share(LOG)['/b'] == 0.25", "share(LOG)['/b']"),
      ("empty", "share([]) == {}", "share([])"),
      ("blanks ignored", "share(['', '  ']) == {}", "share(['', '  '])"),
      ("single path", "share(['/x', '/x'])['/x'] == 1.0", "share(['/x', '/x'])['/x']")],
     ["Count, sum, then divide — and return `{}` before dividing by zero.",
      "`sum(counts.values())` is the denominator; guard it with `if not total`."],
     "def share(lines):\n    ...\n"),
]

AGG2_TASKS = [task(tid, "python", title, diff, pts, "pyodide", brief,
                   starter=(setup + "\n\n" if setup else "") + starter,
                   hints=hints, tests=tests(*trows), solution=sol, setup=setup,
                   area="Aggregation")
              for tid, title, diff, pts, brief, setup, sol, trows, hints, starter in AGG2]

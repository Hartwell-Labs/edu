#!/usr/bin/env python3
"""specs_logs.py — lekcje parsowania i agregacji logów (Python, Pyodide)."""
from gen_tasks import parse_log, task, tests

LOGS = [
    ("log-nginx", "Parse an nginx access line",
     '10.0.0.7 - - [15/Oct/2026:09:12:44] "POST /login" 401 233',
     [("ip", 0), ("method", 5), ("path", 6), ("status", 7)], "nginx access log",
     "The quoted `\"METHOD path\"` spans two elements: element 5 is `\"POST` and element 6 is `/login\"`."),

    ("log-sshd", "Parse an sshd accepted-login line",
     "Accepted password for bartosz from 10.0.0.9 port 51234 ssh2",
     [("user", 3), ("ip", 5), ("port", 7)], "sshd auth log",
     "`Accepted password for <user> from <ip> port <port> ssh2` — indices 3, 5 and 7."),

    ("log-auditd", "Parse an auditd syscall record",
     "type=SYSCALL msg=audit(1792080877.123:456): arch=c000003e syscall=59 success=yes exe=/usr/bin/ls pid=2311",
     [("type", 0), ("arch", 2), ("pid", 6)], "auditd",
     "The record is `key=value` pairs after a `type=` token; the type itself is element 0."),

    ("log-postfix", "Parse a Postfix queue id",
     "postfix/qmgr[2411]: 8A21C3F024: from=<sender@example.com>, size=1024, nrcpt=2 (queue active)",
     [("queue_id", 1), ("size", 3)], "Postfix queue",
     "The daemon token `postfix/qmgr[2411]:` is element 0, so the queue id is element 1."),

    ("log-iptables", "Parse an iptables drop rule",
     "DROP all -- 10.0.0.5 0.0.0.0/0 0.0.0.0/0 tcp -- 445 0.0.0.0/0",
     [("action", 0), ("source", 3), ("port", 8)], "iptables log",
     "Every second field is a flag or the dash; only the fields you care about carry values."),

    ("log-systemd", "Parse a systemd journal line",
     "anvil-lab.service: Started Anvil Lab VM. - Main PID: 2311 (anvil-lab)",
     [("unit", 0), ("action", 1), ("pid", 8)], "systemd journal",
     "The PID appears inside the trailing `- Main PID: N` clause, not in the first two tokens."),

    ("log-fail2ban", "Parse a fail2ban ban line",
     "2026-10-16 09:12:44,123 fail2ban.actions [2311]: NOTICE [sshd] Ban 203.0.113.9",
     [("action", 1), ("ip", 5)], "fail2ban",
     "The timestamp comes first, so the action is element 1 and the address is the last one."),

    ("log-dns", "Parse a dnsmasq query line",
     "Oct 16 09:12:44 gateway dnsmasq[2311]: query[A] lab-a.internal from 10.0.0.7",
     [("name", 2), ("client", 5)], "dnsmasq",
     "The query type sits between `query[` and `]` inside element 2."),

    ("log-docker", "Parse a container log line",
     "2026-10-16T09:12:44.123456789Z worker=anvil level=info msg=\"started\" port=8080",
     [("worker", 1), ("level", 2), ("port", 4)], "container log",
     "Structured logs are `key=value` pairs; keys whose value has spaces are quoted."),

    ("log-haproxy", "Parse an HAProxy frontend line",
     "anvilfe anvilbe 3/0/2/44/109 200 4123 - - ---- 12/340/0/0/0 0/0 \"GET /health HTTP/1.1\"",
     [("frontend", 0), ("backend", 1), ("status", 6)], "HAProxy",
     "The status is the sixth token: `fe be ... status` — count from zero carefully."),

    ("log-kern", "Parse a kernel ring buffer line",
     "<4>[1792080.123456] audit: type=1400 audit(1792080877.123:456): apparmor=\"DENIED\" operation=\"open\"",
     [("level", 0), ("tag", 2)], "kernel log",
     "The leading `<4>` is the log level in angle brackets; the timestamp follows."),

    ("log-cron", "Parse a cron job line",
     "*/15 * * * * root /usr/local/bin/anvil-lab --rotate >> /var/log/anvil.log 2>&1",
     [("user", 0), ("command", 1)], "crontab",
     "After the five schedule fields come the user and the command — the command is one token here."),

    ("log-w3c", "Parse a W3C extended access line",
     '203.0.113.9 - lab [16/Oct/2026:09:12:44 +0200] "GET /admin.php" 404 512 "-" "curl/8.0"',
     [("ip", 0), ("status", 7), ("agent", 10)], "W3C access log",
     "The referrer and the user agent sit at the end, both quoted; the status is the eighth token."),

    ("log-brotli", "Parse a Brotli access log line",
     '10.0.0.7 - - [16/Oct/2026:09:12:44 +0000] "GET / HTTP/2.0" 200 1234 "-" "Mozilla/5.0" "gzip" rt=0.031',
     [("ip", 0), ("status", 7), ("encoding", 11)], "Brotli access log",
     "The negotiated encoding comes before `rt=` at the end of the line."),

    ("log-envoy", "Parse an Envoy access log line",
     '[2026-10-16T09:12:44.123Z] "GET /api HTTP/1.1" 200 - via_upstream - "-" 0 31 3 4 "-" "anvil-cli"',
     [("method", 1), ("status", 2)], "Envoy access log",
     "Envoy wraps the request line in brackets at the start; the status is the third token."),

    ("log-winsec", "Parse a Windows security event",
     "4625 An account failed to log on. Account Name: kija   Source Address: 10.0.0.7",
     [("event_id", 0), ("user", 5), ("ip", 10)], "Windows Security event",
     "Windows messages are human sentences, so the fields sit at fixed positions after the labels."),

    ("log-zap", "Parse a OWASP ZAP alert line",
     "[INFO] 2026-10-16 09:12:44,123 zap.attack - Attack: SQL Injection  Evidence: ' OR 1=1--  URL: /item?id=1",
     [("attack", 6), ("url", 13)], "ZAP scanner log",
     "The attack name follows `Attack:` and the URL follows `URL:` — count the tokens between them."),

    ("log-cloudtrail", "Parse a CloudTrail-shaped event",
     "eventTime=2026-10-16T09:12:44Z eventName=ConsoleLogin sourceIPAddress=203.0.113.9 userIdentity=arn:aws:iam::1:user/kija",
     [("name", 1), ("ip", 2)], "CloudTrail",
     "Everything is `key=value`, so a tiny split on `=` is enough — no positional guessing."),
]

LOG_TASKS = [parse_log(tid, title, sample, fields, difficulty=difficulty, free=False,
                       area=area, hint=hint)
             for tid, title, sample, fields, area, hint, *rest in
             [(a, b, c, d, e, f) for (a, b, c, d, e, f) in LOGS]
             for difficulty in [2]]


# --------------------------------------------------------------- agregacje
AGG = [
    ("log-top-talkers", "Find the noisiest address in a log", 3, 140,
     "One request per line, address first. Complete `top_talkers` so it returns the address "
     "with the most requests, or `None` for an empty log. Lines that do not start with an "
     "address are skipped — log files are full of continuation lines.\n\n"
     "**Stretch:** return a `(ip, count)` tuple, and the whole top-10 as a sorted list.",
     "LOG = '''10.0.0.7 GET /login 401\n10.0.0.7 GET /admin 403\n10.0.0.7 GET /wp-admin 404\n"
     "10.0.0.9 GET / 200\n10.0.0.1 GET /health 200\ntruncated line without an address\n'''\n",
     "def top_talkers(lines):\n"
     "    counts = {}\n"
     "    for line in lines:\n"
     "        parts = line.split()\n"
     "        if not parts:\n"
     "            continue\n"
     "        ip = parts[0]\n"
     "        if ip.count('.') != 3:\n"
     "            continue\n"
     "        counts[ip] = counts.get(ip, 0) + 1\n"
     "    if not counts:\n"
     "        return None\n"
     "    return max(counts.items(), key=lambda kv: kv[1])[0]\n",
     [("busiest wins", "top_talkers(LOG.splitlines()) == '10.0.0.7'", "top_talkers(LOG.splitlines())"),
      ("empty log", "top_talkers([]) is None", "top_talkers([])"),
      ("broken lines skipped", "top_talkers(['oops', '', '10.0.0.1 GET /']) == '10.0.0.1'", "top_talkers(['oops', '', '10.0.0.1 GET /'])"),
      ("all garbage", "top_talkers(['truncated', 'garbage']) is None", "top_talkers(['truncated', 'garbage'])")],
     ["`parts[0].count('.') == 3` is a cheap IPv4 shape check.",
      "`max(counts.items(), key=lambda kv: kv[1])` returns the busiest `(ip, count)` pair.",
      "An empty dict makes `max()` raise — return `None` before you call it."]),

    ("log-status-histogram", "Build a histogram of status codes", 3, 150,
     "Each line ends with an HTTP status. Complete `status_histogram` so it returns a dict of "
     "`status -> count`, ignoring lines whose last field is not a three-digit number.\n\n"
     "**Stretch:** return the codes sorted by frequency, most common first.",
     "LOG = '''GET / 200\nGET /login 401\nGET /admin 403\nGET /wp-admin 404\nGET /health 200\nGET /x 500\nbroken\n'''\n",
     "def status_histogram(lines):\n"
     "    out = {}\n"
     "    for line in lines:\n"
     "        parts = line.split()\n"
     "        if not parts:\n"
     "            continue\n"
     "        code = parts[-1]\n"
     "        if not (code.isdigit() and len(code) == 3):\n"
     "            continue\n"
     "        out[code] = out.get(code, 0) + 1\n"
     "    return out\n",
     [("counts each code", "status_histogram(LOG.splitlines()) == {'200': 2, '401': 1, '403': 1, '404': 1, '500': 1}",
       "status_histogram(LOG.splitlines())"),
      ("broken line ignored", "'broken' not in status_histogram(LOG.splitlines())", "status_histogram(LOG.splitlines())"),
      ("empty input", "status_histogram([]) == {}", "status_histogram([])"),
      ("digits only", "status_histogram(['x 2000']) == {}", "status_histogram(['x 2000'])")],
     ["`str.isdigit()` returns a bool, so chain it with `and` — never compare a string to a number.",
      "The status is the **last** field, so index `-1`, not a fixed position.",
      "Three-digit check: `len(code) == 3` excludes years and ports that ended up in the field."]),

    ("log-unique-users", "Count distinct users in an auth log", 2, 120,
     "Complete `unique_users` so it returns a sorted list of the usernames that appear in the "
     "log. A line has the form `Accepted password for <user> from <ip> ...`; lines that do not "
     "match are skipped.\n\n"
     "**Stretch:** also return how many distinct addresses each user came from.",
     "LOG = '''Accepted password for bartosz from 10.0.0.9 port 1 ssh2\n"
     "Accepted password for kija from 10.0.0.7 port 2 ssh2\n"
     "Accepted password for bartosz from 10.0.0.7 port 3 ssh2\n"
     "Failed password for root from 203.0.113.9 port 4 ssh2\nbroken line\n'''\n",
     "def unique_users(lines):\n"
     "    users = set()\n"
     "    for line in lines:\n"
     "        parts = line.split()\n"
     "        if len(parts) > 4 and parts[0] == 'Accepted' and parts[1] == 'password':\n"
     "            users.add(parts[3])\n"
     "    return sorted(users)\n",
     [("sorted distinct users", "unique_users(LOG.splitlines()) == ['bartosz', 'kija']", "unique_users(LOG.splitlines())"),
      ("failed logins excluded", "'root' not in unique_users(LOG.splitlines())", "unique_users(LOG.splitlines())"),
      ("empty input", "unique_users([]) == []", "unique_users([])")],
     ["`set()` for uniqueness, `sorted()` at the end — two different jobs.",
      "The verb is `parts[0]`: only `Accepted` counts, `Failed` must not.",
      "Guard the length before indexing, or a broken line raises `IndexError`."]),

    ("log-p95", "Find the 95th percentile of response times", 4, 200,
     "Each line ends with a response time in milliseconds. Complete `percentile` so it returns "
     "the p-th percentile using the **nearest-rank** method: sort the values, then take index "
     "`ceil(p / 100 * n) - 1`. An empty list gives `None`.\n\n"
     "**Stretch:** return the p50, p95 and p99 in one call.",
     "VALUES = [12, 30, 45, 120, 200, 7, 88, 91]\n\nimport math\n",
     "import math\n\n"
     "def percentile(values, p):\n"
     "    if not values:\n"
     "        return None\n"
     "    s = sorted(values)\n"
     "    k = max(0, math.ceil(p / 100 * len(s)) - 1)\n"
     "    return s[k]\n",
     [("p95 of the sample", "percentile(VALUES, 95) == 200", "percentile(VALUES, 95)"),
      ("p50", "percentile(VALUES, 50) == 45", "percentile(VALUES, 50)"),
      ("sorting is internal", "percentile([5, 1, 3], 50) == 3", "percentile([5, 1, 3], 50)"),
      ("empty list", "percentile([], 95) is None", "percentile([], 95)"),
      ("single value", "percentile([7], 99) == 7", "percentile([7], 99)")],
     ["Nearest-rank: `ceil(p/100 * n)` is a 1-based rank, so the index is that minus one.",
      "`max(0, ...)` protects you when p is small enough to round down to rank 0.",
      "Sort a copy — never mutate the caller's list."]),

    ("log-dedupe", "Drop duplicate lines while keeping order", 2, 110,
     "Attackers repeat every line. Complete `dedupe` so it returns the lines with duplicates "
     "removed, **first occurrence wins**, and the original order preserved.\n\n"
     "**Stretch:** also return how many duplicates were dropped.",
     "LOG = ['GET /', 'GET /admin', 'GET /', 'GET /health', 'GET /admin']\n",
     "def dedupe(lines):\n"
     "    seen = set()\n"
     "    out = []\n"
     "    for line in lines:\n"
     "        if line in seen:\n"
     "            continue\n"
     "        seen.add(line)\n"
     "        out.append(line)\n"
     "    return out\n",
     [("order preserved", "dedupe(LOG) == ['GET /', 'GET /admin', 'GET /health']", "dedupe(LOG)"),
      ("empty input", "dedupe([]) == []", "dedupe([])"),
      ("input untouched", "len(LOG) == 5", "len(LOG)"),
      ("all duplicates", "dedupe(['a', 'a', 'a']) == ['a']", "dedupe(['a', 'a', 'a'])")],
     ["`seen` + `out` is the whole pattern — no dict, no sorting.",
      "Add to `seen` **after** the check, or everything gets filtered out.",
      "A set gives you membership in O(1); a list would make this quadratic."]),
]

AGG_TASKS = [task(tid, "security", title, diff, pts, "pyodide", brief,
                  area="Aggregation",
                  starter=setup + "\n\ndef %s(lines):\n    ...\n" % tname,
                  hints=hints, tests=tests(*trows), solution=sol, setup=setup)
             for tid, title, diff, pts, brief, setup, sol, trows, hints in AGG
             for tname in [tid.split("-", 1)[1]]]

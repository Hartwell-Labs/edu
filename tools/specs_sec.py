#!/usr/bin/env python3
"""specs_sec.py — bezpieczne API, sekrety, logi i protokoly (Python w Pyodide)."""
from gen_tasks import sec_task, py_task

SEC = [
    sec_task("sec-timingsafe", "Porównanie odporne na pomiar czasu",
             "Secret comparison fails when it gives up as soon as the strings differ — the time it "
             "takes *is* the answer, byte by byte. Complete `safe_eq` so it compares the whole "
             "length regardless, returning `False` for different lengths. `hmac.compare_digest` "
             "does this in C; the point here is to see what it protects against.",
             "import hmac\n\ndef safe_eq(a, b):\n    ...\n",
             "import hmac\n\ndef safe_eq(a, b):\n"
             "    a, b = str(a or ''), str(b or '')\n"
             "    if len(a) != len(b):\n"
             "        return False\n"
             "    return hmac.compare_digest(a.encode(), b.encode())\n",
             [("equal", "safe_eq('token', 'token') is True", "safe_eq('token', 'token')"),
              ("different", "safe_eq('token', 'toke') is False", "safe_eq('token', 'toke')"),
              ("empty both", "safe_eq('', '') is True", "safe_eq('', '')"),
              ("one empty", "safe_eq('', 'a') is False", "safe_eq('', 'a')"),
              ("not a string", "safe_eq(None, None) is True", "safe_eq(None, None)"),
              ("different lengths", "safe_eq('ab', 'abc') is False", "safe_eq('ab', 'abc')")],
             difficulty=3, points=190, setup="import hmac\n", area="Sekrety",
             hint="`compare_digest` expects bytes and always walks the whole buffer."),

    sec_task("sec-entropy-weak", "Zróżnicuj hasła, nie tylko je policz",
             "Complete `strength` so it returns a score from 0 to 4 based on: unique character "
             "classes (lower, upper, digit, other), length, and whether the password is on a tiny "
             "common list. Length must count for the most — length beats complexity, every time.",
             "COMMON = {'password', '123456', 'qwerty', 'letmein', 'admin'}\n\n"
             "def strength(pw):\n    ...\n",
             "import string\nfrom collections import Counter\n\nCOMMON = {'password', '123456', 'qwerty', 'letmein', 'admin'}\n\n"
             "def strength(pw):\n"
             "    p = str(pw or '')\n"
             "    if p.lower() in COMMON:\n"
             "        return 0\n"
             "    if len(p) < 8:\n"
             "        return 1\n"
             "    classes = sum([\n"
             "        any(c in string.ascii_lowercase for c in p),\n"
             "        any(c in string.ascii_uppercase for c in p),\n"
             "        any(c in string.digits for c in p),\n"
             "        any(not c.isalnum() for c in p)])\n"
             "    score = 1\n"
             "    if len(p) >= 12:\n"
             "        score += 1\n"
             "    if len(p) >= 16:\n"
             "        score += 1\n"
             "    if classes >= 3:\n"
             "        score += 1\n"
             "    return min(score, 4)\n",
             [("common is zero", "strength('password') == 0", "strength('password')"),
              ("short is one", "strength('aB3!') == 1", "strength('aB3!')"),
              ("eight chars is two", "strength('aB3!aB3!') == 2", "strength('aB3!aB3!')"),
              ("long wins", "strength('aB3!aB3!aB3!aB3!') == 4", "a sixteen-character password"),
              ("never above four", "strength('x' * 64 + '9!') == 4", "strength('x' * 64 + '9!')"),
              ("empty", "strength('') <= 1", "strength('')")],
             difficulty=4, points=300, setup="import string\nfrom collections import Counter\n", area="Sekrety",
             hint="Length gives two points on its own; the character classes only add the last one."),

    sec_task("sec-redact-log", "Usuń sekret z linii logu",
             "Complete `redact` so every `password=...` value becomes `password=***`, up to the "
             "next whitespace. The value is a token until a space, so a greedy `.*` swallows the "
             "rest of the line. A log is a copy that lives forever — this is where secrets go to "
             "wait to be found.",
             "import re\n\ndef redact(line):\n    ...\n",
             "import re\n\ndef redact(line):\n"
             "    return re.sub(r'(password|token|secret)=[^\\s]+', r'\\1=***', str(line or ''))\n",
             [("one secret", "redact('user=kija password=hunter2') == 'user=kija password=***'", "redact('user=kija password=hunter2')"),
              ("two secrets", "redact('token=a password=b') == 'token=*** password=***'", "redact('token=a password=b')"),
              ("nothing leaks", "'hunter2' not in redact('password=hunter2 ok=1')", "redact('password=hunter2 ok=1')"),
              ("the rest of the line survives", "redact('password=x ok=1').endswith('ok=1')", "redact('password=x ok=1')"),
              ("no secret", "redact('nothing here') == 'nothing here'", "redact('nothing here')"),
              ("empty", "redact('') == ''", "redact('')")],
             difficulty=3, points=200, setup="import re\n", area="Logi",
             hint="`[^\\s]+` stops at the first space — a greedy `.*` would eat the rest of the line."),

    sec_task("sec-perm-mode", "Wylicz właściwe uprawnienia",
             "Complete `mode` so it returns the octal digits of a permission value as a string, "
             "including a leading setuid, setgid or sticky bit. A secret is 0600, a script 0755, a "
             "config 0640 — and getting this wrong is one `chmod` from a world-readable key.",
             "def mode(bits):\n    ...\n",
             "def mode(bits):\n"
             "    special = '' if not (bits & 0o7000) else str((bits >> 9) & 7)\n"
             "    return special + f'{(bits >> 6) & 7}{(bits >> 3) & 7}{bits & 7}'\n",
             [("secret", "mode(0o600) == '600'", "mode(0o600)"),
              ("script", "mode(0o755) == '755'", "mode(0o755)"),
              ("config", "mode(0o640) == '640'", "mode(0o640)"),
              ("sticky", "mode(0o1777) == '1777'", "mode(0o1777)"),
              ("setuid", "mode(0o4755) == '4755'", "mode(0o4755)"),
              ("setgid", "mode(0o2755) == '2755'", "mode(0o2755)")],
             difficulty=2, points=140, area="Uprawnienia",
             hint="The special flags sit at bits 9-11 (sticky, setgid, setuid); then shift by 6 for the owner, 3 for the group, 0 for other."),

    sec_task("sec-umask-effect", "Co robi umask",
             "Complete `after_umask` so it applies a umask to a requested mode — the umask **clears** "
             "bits, it never sets them. `umask 077` on a `0666` file leaves `0600`. A deployment "
             "that sets the umask once fixes a whole class of world-readable files.",
             "def after_umask(requested, umask):\n    ...\n",
             "def after_umask(requested, umask):\n    return requested & ~umask & 0o7777\n",
             [("file 0666 with 077", "after_umask(0o666, 0o077) == 0o600", "after_umask(0o666, 0o077)"),
              ("file 0666 with 022", "after_umask(0o666, 0o022) == 0o644", "after_umask(0o666, 0o022)"),
              ("no umask", "after_umask(0o644, 0o000) == 0o644", "after_umask(0o644, 0o000)"),
              ("umask only clears", "after_umask(0o600, 0o777) == 0o000", "after_umask(0o600, 0o777)"),
              ("umask cannot add", "after_umask(0o600, 0o000) == 0o600", "after_umask(0o600, 0o000)")],
             difficulty=2, points=110, area="Uprawnienia",
             hint="Bitwise AND with the complement: `requested & ~umask`. Never OR — a umask only removes."),

    sec_task("sec-path-traversal-check", "Sprawdź, czy ścieżka wychodzi z katalogu",
             "Complete `escapes` so it returns `True` when a joined path leaves `root`. Normalise "
             "first, then compare with a trailing separator — without that, `/srv/lab-evil` passes "
             "as `/srv/lab`. The `/etc/passwd` style payload is `../` repeated, and encoding is "
             "just another way to spell it.",
             "import posixpath\n\ndef escapes(root, parts):\n    ...\n",
             "import posixpath\n\n"
             "def escapes(root, parts):\n"
             "    full = posixpath.normpath(posixpath.join(root, *parts))\n"
             "    root_n = posixpath.normpath(root)\n"
             "    return not (full == root_n or full.startswith(root_n.rstrip('/') + '/'))\n",
             [("stays inside", "escapes('/srv/lab', ['a', 'b']) is False", "escapes('/srv/lab', ['a', 'b'])"),
              ("one level up", "escapes('/srv/lab', ['../etc']) is True", "escapes('/srv/lab', ['../etc'])"),
              ("deep up", "escapes('/srv/lab', ['../../etc/passwd']) is True", "escapes('/srv/lab', ['../../etc/passwd'])"),
              ("prefix trap", "escapes('/srv/lab', ['../lab-evil']) is True", "escapes('/srv/lab', ['../lab-evil'])"),
              ("root itself", "escapes('/srv/lab', ['.']) is False", "escapes('/srv/lab', ['.'])"),
              ("dot inside", "escapes('/srv/lab', ['./a']) is False", "escapes('/srv/lab', ['./a'])")],
             difficulty=3, points=210, setup="import posixpath\n", area="Sciezki",
             hint="`normpath` first, then `startswith(root + '/')` — never a bare `startswith(root)`."),

    sec_task("sec-crlf-header", "Nagłówek bez CRLF",
             "Complete `header_line` so it builds `name: value` only when the name is "
             "`[A-Za-z0-9-]+` and the value has no CR, LF or NUL. A newline in a value splits the "
             "response and hands the attacker a `Set-Cookie` of their own.",
             "import re\n\ndef header_line(name, value):\n    ...\n",
             "import re\n\ndef header_line(name, value):\n"
             "    if not re.fullmatch(r'[A-Za-z0-9-]+', str(name or '')):\n"
             "        return None\n"
             "    v = str(value)\n"
             "    if any(c in v for c in '\\r\\n\\x00'):\n"
             "        return None\n"
             "    return f'{name}: {v}'\n",
             [("plain", "header_line('X-Id', '7') == 'X-Id: 7'", "header_line('X-Id', '7')"),
              ("cr refused", "header_line('X', 'a\\r\\nX-Evil: 1') is None", "header_line('X', 'a\\r\\nX-Evil: 1')"),
              ("lf refused", "header_line('X', 'a\\nb') is None", "header_line('X', 'a\\nb')"),
              ("nul refused", "header_line('X', 'a\\x00b') is None", "header_line('X', 'a\\x00b')"),
              ("bad name", "header_line('X Y', '1') is None", "header_line('X Y', '1')"),
              ("empty name", "header_line('', '1') is None", "header_line('', '1')")],
             difficulty=3, points=180, setup="import re\n", area="HTTP",
             hint="`re.fullmatch` for the name, then an explicit scan for the three control characters."),

    sec_task("sec-audit-actor", "Kto, co i skąd",
             "A log line without an actor is a rumour. Complete `parse_actor` so it pulls the "
             "user, the source address and the action out of a `key=value` tail, returning `None` "
             "for any of the three that is missing. An audit trail that guesses is worse than none.",
             "LINE = '2026-10-16 09:12:44 action=login user=kija src=10.0.0.7 result=ok'\n",
             "LINE = '2026-10-16 09:12:44 action=login user=kija src=10.0.0.7 result=ok'\n\n"
             "def parse_actor(line):\n"
             "    parts = str(line or '').split()\n"
             "    kv = {}\n"
             "    for p in parts:\n"
             "        if '=' in p:\n"
             "            k, _, v = p.partition('=')\n"
             "            kv[k] = v\n"
             "    keys = ('action', 'user', 'src')\n"
             "    if not all(k in kv and kv[k] for k in keys):\n"
             "        return None\n"
             "    return tuple(kv[k] for k in keys)\n",
             [("all three", "parse_actor(LINE) == ('login', 'kija', '10.0.0.7')", "parse_actor(LINE)"),
              ("no user", "parse_actor('action=login src=10.0.0.7') is None", "parse_actor('action=login src=10.0.0.7')"),
              ("empty value", "parse_actor('action= user=kija src=1.2.3.4') is None", "parse_actor('action= user=kija src=1.2.3.4')"),
              ("no src", "parse_actor('action=login user=kija') is None", "parse_actor('action=login user=kija')"),
              ("empty line", "parse_actor('') is None", "parse_actor('')")],
             difficulty=2, points=150, setup="LINE = '2026-10-16 09:12:44 action=login user=kija src=10.0.0.7 result=ok'\n",
             area="Logi",
             hint="Split the line, keep the `key=value` fields in a dict, then require all three keys."),

    sec_task("sec-strip-ansi", "Usuń sekwencje sterujące z logu",
             "Complete `clean` so ANSI escape sequences are removed, including the colour codes a "
             "tool writes when a value contains them. A raw control character in a log is a "
             "forgery: it lets whoever supplied that value rewrite the lines around it.",
             "import re\n\ndef clean(text):\n    ...\n",
             "import re\n\ndef clean(text):\n"
             "    s = re.sub(r'\\x1b\\[[0-9;?]*[ -/]*[@-~]', '', str(text or ''))\n"
             "    return ''.join(c for c in s if c == '\\t' or c >= ' ')\n",
             [("colour gone", "clean('\\x1b[31mred\\x1b[0m') == 'red'", "clean('a coloured string')"),
              ("text kept", "clean('plain') == 'plain'", "clean('plain')"),
              ("other control chars", "'\\x07' not in clean('a\\x07b')", "clean('a\\x07b')"),
              ("tab survives", "clean('a\\tb') == 'a\\tb'", "clean('a\\tb')"),
              ("empty", "clean('') == ''", "clean('')")],
             difficulty=4, points=280, setup="import re\n", area="Logi",
             hint="`\\x1b\\[` then optional parameters then one final byte in `@-~` is the whole grammar."),

    sec_task("sec-constant-time-loop", "Stały czas bez porównywania znak po znaku",
             "Complete `eq_scan` so it compares two strings without an early exit, using a single "
             "loop that always walks the longer length. The trick is a **difference accumulator** "
             "rather than `if a[i] != b[i]: return False` — which is the bug this lab is about.",
             "def eq_scan(a, b):\n    ...\n",
             "def eq_scan(a, b):\n"
             "    a, b = str(a or ''), str(b or '')\n"
             "    n = max(len(a), len(b))\n"
             "    diff = len(a) ^ len(b)\n"
             "    for i in range(n):\n"
             "        ca = ord(a[i]) if i < len(a) else 0\n"
             "        cb = ord(b[i]) if i < len(b) else 0\n"
             "        diff |= ca ^ cb\n"
             "    return diff == 0\n",
             [("equal", "eq_scan('token', 'token') is True", "eq_scan('token', 'token')"),
              ("different", "eq_scan('token', 'toke') is False", "eq_scan('token', 'toke')"),
              ("different length", "eq_scan('ab', 'abc') is False", "eq_scan('ab', 'abc')"),
              ("empty", "eq_scan('', '') is True", "eq_scan('', '')"),
              ("empty and not", "eq_scan('', 'a') is False", "eq_scan('', 'a')"),
              ("same prefix, late difference", "eq_scan('aaaaaaaaaa', 'aaaaaaaaab') is False", "eq_scan('aaaaaaaaaa', 'aaaaaaaaab')")],
             difficulty=5, points=460, area="Sekrety",
             hint="Accumulate the XOR of every position into `diff` and only test it at the end — never inside the loop."),

    sec_task("sec-json-allowlist", "Przestań wiązać wszystko z prośby",
             "Complete `bind` so it returns only the keys from `allowed` that appear in `payload`, "
             "and never a key starting with `_` or `is_`. Mass assignment is how `role=admin` gets "
             "into an account record.",
             "def bind(payload, allowed):\n    ...\n",
             "def bind(payload, allowed):\n"
             "    out = {}\n"
             "    for k in allowed:\n"
             "        if k.startswith('_') or k.startswith('is_'):\n"
             "            continue\n"
             "        if k in payload:\n"
             "            out[k] = payload[k]\n"
             "    return out\n",
             [("only what is allowed", "bind({'name': 'kija', 'role': 'admin'}, ['name']) == {'name': 'kija'}", "a payload carrying an extra role"),
              ("no secret role filter", "bind({'role': 'admin'}, ['role']) == {'role': 'admin'}", "the fix is the allow-list itself, not a role blacklist"),
              ("extra field dropped", "bind({'name': 'k', 'role': 'a'}, ['name']) == {'name': 'k'}", "bind({'name': 'k', 'role': 'a'}, ['name'])"),
              ("missing stays missing", "bind({'a': 1}, ['a', 'b']) == {'a': 1}", "bind({'a': 1}, ['a', 'b'])"),
              ("private key refused", "bind({'_id': 1, 'name': 'k'}, ['_id', 'name']) == {'name': 'k'}", "bind({'_id': 1, 'name': 'k'}, ['_id', 'name'])"),
              ("is_ flag refused", "bind({'is_admin': True, 'name': 'k'}, ['is_admin', 'name']) == {'name': 'k'}", "bind({'is_admin': True, 'name': 'k'}, ['is_admin', 'name'])"),
              ("empty", "bind({}, ['a']) == {}", "bind({}, ['a'])")],
             difficulty=2, points=150, area="API",
             hint="Iterate the **allow-list**, never the payload — that is the whole point of the fix."),

    sec_task("sec-rate-sliding", "Okno przesuwne, nie dwie minuty",
             "A fixed window lets an attacker send 2× the limit across a boundary. Complete "
             "`limited` so it accepts a timestamp only when fewer than `limit` requests fall in the "
             "preceding `window` seconds — a sliding window. A deque of timestamps is the whole "
             "implementation.",
             "from collections import deque\n\ndef limited(window, limit):\n    ...\n",
             "from collections import deque\n\n"
             "def limited(window, limit):\n"
             "    q = deque()\n"
             "    for t in sorted(window):\n"
             "        while q and t - q[0] >= 60:\n"
             "            q.popleft()\n"
             "        if len(q) >= limit:\n"
             "            return False\n"
             "        q.append(t)\n"
             "    return True\n",
             [("under the limit", "limited([0, 10, 20], 3) is True", "limited([0, 10, 20], 3)"),
              ("over the limit", "limited([0, 10, 20, 30], 3) is False", "limited([0, 10, 20, 30], 3)"),
              ("old ones expire", "limited([0, 70, 80], 2) is True", "limited([0, 70, 80], 2)"),
              ("boundary is excluded", "limited([0, 60], 2) is True", "limited([0, 60], 2)"),
              ("empty", "limited([], 1) is True", "limited([], 1)"),
              ("single", "limited([5], 1) is True", "limited([5], 1)")],
             difficulty=4, points=300, setup="from collections import deque\n", area="Rate limiting",
             hint="Sort, then drop everything older than `t - 60` from the front of the deque before counting."),

    sec_task("sec-ips-spoof", "Który nagłówek ufasz",
             "Complete `client_ip` so it returns the address from `X-Forwarded-For` **only** when "
             "`trusted` says the proxy may set it, and the peer address otherwise. A forwarded "
             "header straight from the client is a rate limiter with a self-service button.",
             "def client_ip(peer, forwarded, trusted):\n    ...\n",
             "def client_ip(peer, forwarded, trusted):\n"
             "    if not trusted:\n"
             "        return peer\n"
             "    for part in str(forwarded or '').split(','):\n"
             "        part = part.strip()\n"
             "        if part:\n"
             "            return part\n"
             "    return peer\n",
             [("untrusted falls back", "client_ip('10.0.0.1', '9.9.9.9', False) == '10.0.0.1'", "client_ip('10.0.0.1', '9.9.9.9', False)"),
              ("trusted uses it", "client_ip('10.0.0.1', '9.9.9.9', True) == '9.9.9.9'", "client_ip('10.0.0.1', '9.9.9.9', True)"),
              ("first of a chain", "client_ip('10.0.0.1', '9.9.9.9, 8.8.8.8', True) == '9.9.9.9'", "client_ip('10.0.0.1', '9.9.9.9, 8.8.8.8', True)"),
              ("empty header", "client_ip('10.0.0.1', '', True) == '10.0.0.1'", "client_ip('10.0.0.1', '', True)"),
              ("spaces trimmed", "client_ip('10.0.0.1', '  9.9.9.9  ', True) == '9.9.9.9'", "client_ip('10.0.0.1', '  9.9.9.9  ', True)")],
             difficulty=3, points=190, area="HTTP",
             hint="The trust decision comes first; only then do you look at the header."),

    sec_task("sec-uuid-version", "Czy ten identyfikator jest zgadywalny",
             "Complete `predictable` so it returns `True` for a sequential or counter-based id "
             "(`user1`, `user2`, a plain integer) and `False` for something with real entropy. An "
             "IDOR is one guessed number away, so the shape of your ids is a security decision.",
             "import re\n\ndef predictable(uid):\n    ...\n",
             "import re\n\n"
             "def predictable(uid):\n"
             "    s = str(uid or '')\n"
             "    if not s:\n"
             "        return True\n"
             "    if s.isdigit():\n"
             "        return True\n"
             "    if re.fullmatch(r'(user|item|order)[-_]?\\d+', s, re.I):\n"
             "        return True\n"
             "    return len(set(s)) < 8\n",
             [("plain integer", "predictable(1042) is True", "predictable(1042)"),
              ("prefixed counter", "predictable('user1') is True", "predictable('user1')"),
              ("dashed counter", "predictable('item-42') is True", "predictable('item-42')"),
              ("real id", "predictable('a3f9c2e1b8d4') is False", "predictable('a3f9c2e1b8d4')"),
              ("empty", "predictable('') is True", "predictable('')"),
              ("short", "predictable('abc') is True", "predictable('abc')")],
             difficulty=3, points=200, setup="import re\n", area="API",
             hint="Two shapes to catch (digits, `word` + digits) and one heuristic: too few distinct characters."),

    sec_task("sec-tls-verify", "Weryfikacja to nie jest brak weryfikacji",
             "Complete `verify_ok` so it returns `True` only when the certificate is valid, the "
             "hostname matches and the chain is trusted. `verify=False` is the single most common "
             "line in shipped code, and it removes the only thing TLS does for you.",
             "VERIFY_FALSE = {'ssl_verify': False, 'host_check': False}\n\n"
             "def verify_ok(config, cert_valid, host_match, chain_ok):\n    ...\n",
             "VERIFY_FALSE = {'ssl_verify': False, 'host_check': False}\n\n"
             "def verify_ok(config, cert_valid, host_match, chain_ok):\n"
             "    if not config.get('ssl_verify', True):\n"
             "        return False\n"
             "    if not config.get('host_check', True):\n"
             "        return False\n"
             "    return bool(cert_valid and host_match and chain_ok)\n",
             [("all good", "verify_ok({'ssl_verify': True, 'host_check': True}, True, True, True) is True", "verify_ok({'ssl_verify': True, 'host_check': True}, True, True, True)"),
              ("verify off", "verify_ok(VERIFY_FALSE, True, True, True) is False", "verify_ok(VERIFY_FALSE, True, True, True)"),
              ("host check off", "verify_ok({'ssl_verify': True, 'host_check': False}, True, True, True) is False", "host check disabled"),
              ("expired", "verify_ok({'ssl_verify': True, 'host_check': True}, False, True, True) is False", "an expired certificate"),
              ("wrong host", "verify_ok({'ssl_verify': True, 'host_check': True}, True, False, True) is False", "a name mismatch"),
              ("untrusted chain", "verify_ok({'ssl_verify': True, 'host_check': True}, True, True, False) is False", "an untrusted chain")],
             difficulty=2, points=160, area="TLS",
             hint="The configuration gates the check; only then do the three facts matter."),

    sec_task("sec-cache-key", "Klucz cache, który nie miesza użytkowników",
             "Complete `cache_key` so it includes the tenant **and** the permission set in the key. "
             "A key missing either serves one user's rows to another — the bug is invisible until "
             "somebody notices.",
             "def cache_key(user_id, tenant, perms, path):\n    ...\n",
             "def cache_key(user_id, tenant, perms, path):\n"
             "    p = ','.join(sorted(perms or []))\n"
             "    return f'{tenant}:{p}:{user_id}:{path}'\n",
             [("deterministic", "cache_key(1, 'a', ['r'], '/x') == cache_key(1, 'a', ['r'], '/x')", "the same inputs twice"),
              ("tenant changes it", "cache_key(1, 'a', ['r'], '/x') != cache_key(1, 'b', ['r'], '/x')", "a different tenant"),
              ("perms change it", "cache_key(1, 'a', ['r'], '/x') != cache_key(1, 'a', ['rw'], '/x')", "different permissions"),
              ("user changes it", "cache_key(1, 'a', ['r'], '/x') != cache_key(2, 'a', ['r'], '/x')", "a different user"),
              ("order does not matter", "cache_key(1, 'a', ['r', 'w'], '/x') == cache_key(1, 'a', ['w', 'r'], '/x')", "permuted permissions"),
              ("path changes it", "cache_key(1, 'a', ['r'], '/x') != cache_key(1, 'a', ['r'], '/y')", "a different path")],
             difficulty=3, points=210, area="API",
             hint="Sort the permissions first, then join every part with something that cannot appear inside a value."),

    sec_task("sec-cli-args", "Argumenty bez shella",
             "Complete `build_cmd` so it returns a list, never a string — `subprocess` with a list "
             "and `shell=False` passes no argument to a shell. Joining the parts with spaces is the "
             "bug that turns `; rm -rf /` in a filename into a command.",
             "def build_cmd(program, args):\n    ...\n",
             "def build_cmd(program, args):\n"
             "    return [str(program)] + [str(a) for a in (args or [])]\n",
             [("program and args", "build_cmd('ls', ['-l', '/srv']) == ['ls', '-l', '/srv']", "build_cmd('ls', ['-l', '/srv'])"),
              ("no args", "build_cmd('id', []) == ['id']", "build_cmd('id', [])"),
              ("still a list", "isinstance(build_cmd('id', []), list)", "build_cmd('id', [])"),
              ("numbers become text", "build_cmd('sleep', [1]) == ['sleep', '1']", "build_cmd('sleep', [1])"),
              ("injection stays one argument", "build_cmd('grep', ['a; rm -rf /']) == ['grep', 'a; rm -rf /']", "an argument with a semicolon"),
              ("none is empty", "build_cmd('id', None) == ['id']", "build_cmd('id', None)")]),
    sec_task("sec-insecure-deser", "Nigdy nie deserializuj od niezaufanego",
             "`pickle.loads` on data you did not produce is remote code execution, not a bug. "
             "Complete `safe_loads` so it only accepts JSON and returns `None` for anything else — "
             "the habit to build is \"untrusted input is text, and only text\".",
             "import json\n\ndef safe_loads(raw):\n    ...\n",
             "import json\n\ndef safe_loads(raw):\n"
             "    if isinstance(raw, (bytes, bytearray)):\n"
             "        try:\n"
             "            raw = raw.decode('utf-8')\n"
             "        except UnicodeDecodeError:\n"
             "            return None\n"
             "    if not isinstance(raw, str):\n"
             "        return None\n"
             "    try:\n"
             "        return json.loads(raw)\n"
             "    except Exception:\n"
             "        return None\n",
             [("object", "safe_loads('{\"a\": 1}') == {'a': 1}", "safe_loads('{\"a\": 1}')"),
              ("list", "safe_loads('[1, 2]') == [1, 2]", "safe_loads('[1, 2]')"),
              ("bytes", "safe_loads(b'{\"a\": 1}') == {'a': 1}", "safe_loads(b'{\"a\": 1}')"),
              ("malformed", "safe_loads('{oops') is None", "safe_loads('{oops')"),
              ("not text at all", "safe_loads(12345) is None", "safe_loads(12345)"),
              ("binary blob", "safe_loads(b'\\x80\\x04\\x95pickle') is None", "a pickled stream")],
             difficulty=3, points=200, setup="import json\n", area="Dane",
             hint="Type-check first, then parse inside `try`. A pickle payload is not valid JSON, so it returns `None`."),

    sec_task("sec-rotate-keys", "Rotacja klucza bez zrywu",
             "Complete `current_key` so it returns the newest key that has not expired, and `None` "
             "if there is none. Rotation only works if a new key is accepted **before** the old one "
             "stops working — a rotation you do in one step is an outage.",
             "import time\n\nKEYS = [{'id': 'k1', 'expires': 100}, {'id': 'k2', 'expires': 200}, {'id': 'k3', 'expires': 50}]\n\n"
             "def current_key(now):\n    ...\n",
             "KEYS = [{'id': 'k1', 'expires': 100}, {'id': 'k2', 'expires': 200}, {'id': 'k3', 'expires': 50}]\n\n"
             "def current_key(now):\n"
             "    live = [k for k in KEYS if k['expires'] > now]\n"
             "    if not live:\n"
             "        return None\n"
             "    return max(live, key=lambda k: k['expires'])['id']\n",
             [("newest live", "current_key(60) == 'k2'", "current_key(60)"),
              ("k1 still live", "current_key(99) == 'k2'", "current_key(99)"),
              ("k1 expires", "current_key(150) == 'k2'", "current_key(150)"),
              ("k2 is the last", "current_key(199) == 'k2'", "current_key(199)"),
              ("all expired", "current_key(500) is None", "current_key(500)"),
              ("k3 is already gone", "current_key(60) == 'k2'", "an expired key is never chosen")],
             difficulty=3, points=190, setup="import time\n", area="Sekrety",
             hint="Filter first, then take the **largest** expiry among what is left."),

    sec_task("sec-audit-changes", "Kto zmienił to pole",
             "Complete `diff_fields` so it returns the fields whose value differs between two "
             "records, but never the ones that only changed because the record was touched "
             "(`updated_at`). An audit log full of noise is an audit log nobody reads.",
             "def diff_fields(before, after, ignore=('updated_at',)):\n    ...\n",
             "def diff_fields(before, after, ignore=('updated_at',)):\n"
             "    out = {}\n"
             "    for k in set(before) | set(after):\n"
             "        if k in (ignore or ()):\n"
             "            continue\n"
             "        if before.get(k) != after.get(k):\n"
             "            out[k] = (before.get(k), after.get(k))\n"
             "    return out\n",
             [("one change", "diff_fields({'a': 1}, {'a': 2}) == {'a': (1, 2)}", "diff_fields({'a': 1}, {'a': 2})"),
              ("timestamp ignored", "diff_fields({'a': 1, 'updated_at': 1}, {'a': 1, 'updated_at': 2}) == {}", "timestamp noise only"),
              ("added field", "diff_fields({}, {'a': 1}) == {'a': (None, 1)}", "a new field"),
              ("removed field", "diff_fields({'a': 1}, {}) == {'a': (1, None)}", "a removed field"),
              ("no change", "diff_fields({'a': 1}, {'a': 1}) == {}", "diff_fields({'a': 1}, {'a': 1})"),
              ("several", "len(diff_fields({'a': 1, 'b': 2}, {'a': 9, 'b': 2})) == 1", "one of two fields")],
             difficulty=3, points=190, area="Logi",
             hint="Iterate the union of both key sets, skip the ignored ones, and record the pair."),

    sec_task("sec-port-allow", "Dozwolone porty jako allow-list",
             "Complete `allowed` so it returns `True` only for a port in the allow-list. A "
             "block-list of \"interesting\" ports is a losing game: 65 535 ports, and a block-list "
             "of the ones that attack you this month.",
             "ALLOW = {22, 80, 443, 8080}\n\ndef allowed(port):\n    ...\n",
             "ALLOW = {22, 80, 443, 8080}\n\ndef allowed(port):\n    return int(port) in ALLOW\n",
             [("ssh", "allowed(22) is True", "allowed(22)"),
              ("https", "allowed(443) is True", "allowed(443)"),
              ("database refused", "allowed(3306) is False", "allowed(3306)"),
              ("string port", "allowed('8080') is True", "allowed('8080')"),
              ("privileged refused", "allowed(1) is False", "allowed(1)"),
              ("out of range", "allowed(70000) is False", "allowed(70000)")],
             difficulty=2, points=90, area="Sieć",
             hint="A set lookup is the whole implementation — `in` is already the membership test."),

    sec_task("sec-user-agent", "Nie ufaj nagłówkowi User-Agent",
             "Complete `client_kind` so it classifies a user agent by what it **does**, and returns "
             "'unknown' for anything unrecognised. A User-Agent is a self-declared string: the "
             "only safe reading of it is \"whoever wrote this wanted to be seen as that\".",
             "KNOWN = {'curl/': 'cli', 'python-requests/': 'script', 'sqlmap/': 'scanner', 'Mozilla/': 'browser'}\n\n"
             "def client_kind(ua):\n    ...\n",
             "KNOWN = {'curl/': 'cli', 'python-requests/': 'script', 'sqlmap/': 'scanner', 'Mozilla/': 'browser'}\n\n"
             "def client_kind(ua):\n"
             "    s = str(ua or '').lower()\n"
             "    for prefix, kind in KNOWN.items():\n"
             "        if s.startswith(prefix.lower()):\n"
             "            return kind\n"
             "    return 'unknown'\n",
             [("curl", "client_kind('curl/8.0') == 'cli'", "client_kind('curl/8.0')"),
              ("browser", "client_kind('Mozilla/5.0') == 'browser'", "client_kind('Mozilla/5.0')"),
              ("scanner", "client_kind('sqlmap/1.7') == 'scanner'", "client_kind('sqlmap/1.7')"),
              ("empty", "client_kind('') == 'unknown'", "client_kind('')"),
              ("case insensitive", "client_kind('CURL/8.0') == 'cli'", "client_kind('CURL/8.0')"),
              ("impersonation is still just a claim", "client_kind('curl/8.0 evil') == 'cli'", "client_kind('curl/8.0 evil')")],
             difficulty=2, points=120, area="HTTP",
             hint="Lowercase once, then a prefix loop — and remember the answer is a *claim*."),

    sec_task("sec-time-parse", "Czas z serwera to tekst",
             "Complete `parse_ts` so it accepts an ISO-8601 timestamp and returns a UNIX time, or "
             "`None` for anything it does not understand. Never let a malformed date raise inside a "
             "request handler — that is a free denial of service.",
             "from datetime import datetime\n\ndef parse_ts(text):\n    ...\n",
             "from datetime import datetime\n\n"
             "def parse_ts(text):\n"
             "    s = str(text or '').strip().replace('Z', '+00:00')\n"
             "    try:\n"
             "        return datetime.fromisoformat(s).timestamp()\n"
             "    except Exception:\n"
             "        return None\n",
             [("plain", "parse_ts('2026-10-16T09:12:44') > 0", "parse_ts('2026-10-16T09:12:44')"),
              ("zulu", "parse_ts('2026-10-16T09:12:44Z') > 0", "parse_ts('2026-10-16T09:12:44Z')"),
              ("fractional", "parse_ts('2026-10-16T09:12:44.123Z') > 0", "parse_ts('2026-10-16T09:12:44.123Z')"),
              ("garbage", "parse_ts('yesterday') is None", "parse_ts('yesterday')"),
              ("empty", "parse_ts('') is None", "parse_ts('')"),
              ("impossible date", "parse_ts('2026-13-45') is None", "parse_ts('2026-13-45')")],
             difficulty=2, points=140, setup="from datetime import datetime\n", area="Dane",
             hint="Normalise the `Z` to `+00:00` first, then one `try` around the whole parse."),
]

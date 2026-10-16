#!/usr/bin/env python3
"""specs_net2.py — adresy, porty, nagłówki HTTP i TLS (Python w Pyodide)."""
from gen_tasks import sec_task, py_task

NET = [
    sec_task("net2-ip-valid", "Validate an IPv4 address",
             "Complete `is_ipv4` so it accepts only a dotted quad of four decimal octets in "
             "0–255 with no leading zeros and no extra parts. `0.0.0.0` is valid as a value and "
             "invalid as a destination — validation is one question, policy is another.",
             "def is_ipv4(text):\n    ...\n",
             "def is_ipv4(text):\n"
             "    parts = str(text).split('.')\n"
             "    if len(parts) != 4:\n"
             "        return False\n"
             "    for p in parts:\n"
             "        if not p.isdigit() or (len(p) > 1 and p[0] == '0') or int(p) > 255:\n"
             "            return False\n"
             "    return True\n",
             [("plain", "is_ipv4('10.0.0.7') is True", "is_ipv4('10.0.0.7')"),
              ("max octet", "is_ipv4('255.255.255.255') is True", "is_ipv4('255.255.255.255')"),
              ("zero", "is_ipv4('0.0.0.0') is True", "is_ipv4('0.0.0.0')"),
              ("too many parts", "is_ipv4('1.2.3.4.5') is False", "is_ipv4('1.2.3.4.5')"),
              ("octet over 255", "is_ipv4('1.2.3.256') is False", "is_ipv4('1.2.3.256')"),
              ("leading zero", "is_ipv4('1.2.3.04') is False", "is_ipv4('1.2.3.04')"),
              ("not a number", "is_ipv4('1.2.3.x') is False", "is_ipv4('1.2.3.x')")],
             difficulty=2, points=140, area="Addresses",
             hint="`str.isdigit()` first, then a separate check for the leading zero — `int('04')` would happily accept it."),

    sec_task("net2-cidr", "Which addresses a CIDR block contains",
             "Complete `in_cidr` so it reports whether an address sits inside `10.0.0.0/8`. The "
             "prefix length decides how many leading bits must match, and an address with a prefix "
             "not on a byte boundary is where hand-rolled code breaks — shifting by `32 - bits` "
             "handles every case.",
             "def in_cidr(ip, cidr):\n    ...\n",
             "def to_int(text):\n"
             "    return sum(int(p) << (24 - 8 * i) for i, p in enumerate(text.split('.')))\n\n"
             "def in_cidr(ip, cidr):\n"
             "    net, bits = cidr.split('/')\n"
             "    bits = int(bits)\n"
             "    mask = (0xffffffff << (32 - bits)) & 0xffffffff if bits else 0\n"
             "    return (to_int(ip) & mask) == (to_int(net) & mask)\n",
             [("inside", "in_cidr('10.1.2.3', '10.0.0.0/8') is True", "in_cidr('10.1.2.3', '10.0.0.0/8')"),
              ("outside", "in_cidr('11.1.2.3', '10.0.0.0/8') is False", "in_cidr('11.1.2.3', '10.0.0.0/8')"),
              ("single host", "in_cidr('10.0.0.7', '10.0.0.7/32') is True", "in_cidr('10.0.0.7', '10.0.0.7/32')"),
              ("other host", "in_cidr('10.0.0.8', '10.0.0.7/32') is False", "in_cidr('10.0.0.8', '10.0.0.7/32')"),
              ("/24", "in_cidr('10.0.0.200', '10.0.0.0/24') is True", "in_cidr('10.0.0.200', '10.0.0.0/24')"),
              ("/24 outside", "in_cidr('10.0.1.1', '10.0.0.0/24') is False", "in_cidr('10.0.1.1', '10.0.0.0/24')"),
              ("/0 is everything", "in_cidr('8.8.8.8', '0.0.0.0/0') is True", "in_cidr('8.8.8.8', '0.0.0.0/0')")],
             difficulty=4, points=300, area="Addresses",
             hint="Convert both to one integer, build a mask with `<< (32 - bits)`, then compare the masked values."),

    sec_task("net2-port-name", "Map a port number to its service",
             "Complete `service` so it returns the name for a well-known port and `None` for "
             "anything else. Ports below 1024 are the privileged ones; a service that binds to "
             "one of them is a different conversation from one that binds to 8080.",
             "PORTS = {22: 'ssh', 25: 'smtp', 53: 'dns', 80: 'http', 443: 'https', 3306: 'mysql', 5432: 'postgres', 6379: 'redis'}\n\n"
             "def service(port):\n    ...\n",
             "PORTS = {22: 'ssh', 25: 'smtp', 53: 'dns', 80: 'http', 443: 'https', 3306: 'mysql', 5432: 'postgres', 6379: 'redis'}\n\n"
             "def service(port):\n    return PORTS.get(int(port))\n",
             [("known", "service(22) == 'ssh'", "service(22)"),
              ("string port", "service('443') == 'https'", "service('443')"),
              ("unknown", "service(31337) is None", "service(31337)"),
              ("database", "service(5432) == 'postgres'", "service(5432)")],
             difficulty=2, points=70, area="Addresses",
             hint="`dict.get` returns `None` for a miss — do not reach for `KeyError`."),

    sec_task("net2-split-hostport", "Split host:port, including IPv6",
             "Complete `split_hostport` so `'example.com:8080'` gives `('example.com', 8080)` and "
             "`'[::1]:9200'` gives `('::1', 9200)`. Brackets are how an IPv6 literal survives a "
             "colon-separated pair; a missing port gives `None`, and garbage gives `(None, None)` "
             "instead of raising.",
             "def split_hostport(text):\n    ...\n",
             "def split_hostport(text):\n"
             "    text = str(text or '').strip()\n"
             "    if text.startswith('['):\n"
             "        end = text.find(']')\n"
             "        if end == -1:\n"
             "            return None, None\n"
             "        host, rest = text[1:end], text[end + 1:]\n"
             "        port = rest[1:] if rest.startswith(':') else None\n"
             "        return host, int(port) if port and port.isdigit() else None\n"
             "    if ':' not in text:\n"
             "        return text or None, None\n"
             "    host, _, port = text.rpartition(':')\n"
             "    if not port.isdigit():\n"
             "        return None, None\n"
             "    return host or None, int(port)\n",
             [("host and port", "split_hostport('example.com:8080') == ('example.com', 8080)", "split_hostport('example.com:8080')"),
              ("host only", "split_hostport('example.com') == ('example.com', None)", "split_hostport('example.com')"),
              ("ipv6 with port", "split_hostport('[::1]:9200') == ('::1', 9200)", "split_hostport('[::1]:9200')"),
              ("ipv6 alone", "split_hostport('[::1]') == ('::1', None)", "split_hostport('[::1]')"),
              ("port zero kept", "split_hostport('h:0') == ('h', 0)", "split_hostport('h:0')"),
              ("not a port", "split_hostport('h:http') == (None, None)", "split_hostport('h:http')")],
             difficulty=4, points=280, area="Addresses",
             hint="Handle the bracketed IPv6 form first, then `rpartition(':')` for everything else."),

    sec_task("net2-header-parse", "Parse one raw HTTP header block",
             "Complete `parse_headers` so it returns a dict of lower-cased header names to values, "
             "with the value stripped. A repeated header keeps the **last** value, and a line with "
             "no colon is skipped — a malformed request should not take the server down.",
             "def parse_headers(block):\n    ...\n",
             "def parse_headers(block):\n"
             "    out = {}\n"
             "    for line in (block or '').splitlines():\n"
             "        if ':' not in line:\n"
             "            continue\n"
             "        name, _, value = line.partition(':')\n"
             "        name = name.strip().lower()\n"
             "        if name:\n"
             "            out[name] = value.strip()\n"
             "    return out\n",
             [("one header", "parse_headers('Host: a.pl') == {'host': 'a.pl'}", "parse_headers('Host: a.pl')"),
              ("value trimmed", "parse_headers('Accept:  json ') == {'accept': 'json'}", "parse_headers('Accept:  json ')"),
              ("last wins", "parse_headers('X: 1\\nX: 2') == {'x': '2'}", "parse_headers('X: 1\\nX: 2')"),
              ("no colon skipped", "parse_headers('junk') == {}", "parse_headers('junk')"),
              ("empty", "parse_headers('') == {}", "parse_headers('')")],
             difficulty=2, points=120, area="HTTP",
             hint="`partition(':')` splits once and always returns three parts; `strip()` both sides."),

    sec_task("net2-header-injection", "Refuse a newline in a header value",
             "Complete `safe_header` so it returns `name: value` only when the name matches "
             "`[A-Za-z0-9-]+` and the value carries no CR, LF or NUL. Otherwise it returns `None`. "
             "A newline in a value is response splitting — the request dies before it is sent.",
             "import re\n\ndef safe_header(name, value):\n    ...\n",
             "import re\n\ndef safe_header(name, value):\n"
             "    if not re.fullmatch(r'[A-Za-z0-9-]+', name or ''):\n"
             "        return None\n"
             "    if any(c in value for c in '\\r\\n\\x00'):\n"
             "        return None\n"
             "    return f'{name}: {value}'\n",
             [("plain", "safe_header('X-Id', '7') == 'X-Id: 7'", "safe_header('X-Id', '7')"),
              ("crlf refused", "safe_header('X-Id', 'a\\r\\nSet-Cookie: x=1') is None", "CRLF in the value"),
              ("newline refused", "safe_header('X', 'a\\nb') is None", "newline in the value"),
              ("nul refused", "safe_header('X', 'a\\x00b') is None", "NUL in the value"),
              ("bad name", "safe_header('X Id', '7') is None", "a space in the name"),
              ("empty name", "safe_header('', '7') is None", "an empty name")],
             difficulty=3, points=190, setup="import re\n", area="HTTP",
             hint="Validate the name with a fullmatch, then test the value for control characters explicitly."),

    sec_task("net2-host-normalise", "Normalise a Host header safely",
             "Complete `normalise_host` so it lowercases the name, strips a trailing dot, and "
             "returns `None` when a `/`, `@` or whitespace sneaks in. A Host header is a **name**, "
             "not a URL — anything path-like in it is an attempt at a cache-poisoning or password-"
             "reset link.",
             "def normalise_host(value):\n    ...\n",
             "def normalise_host(value):\n"
             "    v = str(value or '').strip().lower()\n"
             "    if not v or any(c in v for c in '/@ \\t'):\n"
             "        return None\n"
             "    return v.rstrip('.')\n",
             [("lowercased", "normalise_host('Example.COM') == 'example.com'", "normalise_host('Example.COM')"),
              ("trailing dot", "normalise_host('example.com.') == 'example.com'", "normalise_host('example.com.')"),
              ("port kept", "normalise_host('example.com:8443') == 'example.com:8443'", "normalise_host('example.com:8443')"),
              ("path refused", "normalise_host('example.com/x') is None", "normalise_host('example.com/x')"),
              ("userinfo refused", "normalise_host('a@evil.pl') is None", "normalise_host('a@evil.pl')"),
              ("whitespace refused", "normalise_host('a b') is None", "normalise_host('a b')"),
              ("empty", "normalise_host('') is None", "normalise_host('')")],
             difficulty=2, points=150, area="HTTP",
             hint="Reject first, normalise after — strip, lower, then a single check for the forbidden characters."),

    sec_task("net2-redirect-same", "Only redirect to a host you know",
             "Complete `safe_redirect` so it returns the target only when it is a path starting "
             "with a single `/`, and `None` for anything with a host in it: `//evil.example` is "
             "protocol-relative and will happily send the user off-site. Backslashes count too — "
             "browsers treat them as slashes.",
             "def safe_redirect(target):\n    ...\n",
             "def safe_redirect(target):\n"
             "    t = str(target or '')\n"
             "    if not t.startswith('/'):\n"
             "        return None\n"
             "    if t.startswith('//') or '\\\\' in t or ':' in t.split('/')[0]:\n"
             "        return None\n"
             "    return t\n",
             [("plain path", "safe_redirect('/dashboard') == '/dashboard'", "safe_redirect('/dashboard')"),
              ("query kept", "safe_redirect('/a?b=1') == '/a?b=1'", "safe_redirect('/a?b=1')"),
              ("protocol relative refused", "safe_redirect('//evil.example') is None", "safe_redirect('//evil.example')"),
              ("backslash refused", "safe_redirect('/\\\\evil.example') is None", "safe_redirect('/\\\\evil.example')"),
              ("absolute refused", "safe_redirect('https://evil.example') is None", "safe_redirect('https://evil.example')"),
              ("relative refused", "safe_redirect('dashboard') is None", "safe_redirect('dashboard')"),
              ("empty", "safe_redirect('') is None", "safe_redirect('')")],
             difficulty=3, points=220, area="HTTP",
             hint="A single leading slash is required, and the second character must not be a slash or a backslash."),

    sec_task("net2-tls-sni", "Read the SNI host out of a ClientHello",
             "A ClientHello lays its fields out in a fixed order: record header, handshake type, "
             "client version, 32 bytes of random, a session id whose length byte sits at offset "
             "**43**, the cipher suites, the compression methods, and only then the extensions — "
             "where the server name lives. Complete `sni_host` so it walks that order and returns "
             "the hostname, or `None` when the record is not a ClientHello. One byte of "
             "misalignment and you return the wrong name.",
             "def sni_host(raw):\n    ...\n",
             "def sni_host(raw):\n"
             "    b = bytes(raw or b'')\n"
             "    try:\n"
             "        if b[0] != 0x16 or b[5] != 0x01:\n"
             "            return None\n"
             "        i = 44 + b[43]                       # koniec session id\n"
             "        i += 2 + int.from_bytes(b[i:i + 2], 'big')   # cipher suites\n"
             "        i += 1 + b[i]                      # compression methods\n"
             "        end = i + 2 + int.from_bytes(b[i:i + 2], 'big')   # extensions\n"
             "        i += 2\n"
             "        while i + 4 <= end:\n"
             "            etype = int.from_bytes(b[i:i + 2], 'big')\n"
             "            elen = int.from_bytes(b[i + 2:i + 4], 'big')\n"
             "            if etype == 0x0000:              # server_name\n"
             "                p = i + 4 + 2 + 1\n"
             "                n = int.from_bytes(b[p:p + 2], 'big')\n"
             "                return b[p + 2:p + 2 + n].decode('ascii')\n"
             "            i += 4 + elen\n"
             "        return None\n"
             "    except (IndexError, UnicodeDecodeError, ValueError):\n"
             "        return None\n",
             [("a real hello", "sni_host(HELLO) == 'lab.example.com'", "a ClientHello with an SNI extension"),
              ("no SNI extension", "sni_host(HELLO_NO_SNI) is None", "a ClientHello with only a supported-versions extension"),
              ("not a handshake record", "sni_host(bytes([0x17]) + HELLO[1:]) is None", "an application-data record"),
              ("not a client hello", "sni_host(HELLO[:5] + bytes([0x02]) + HELLO[6:]) is None", "a server hello"),
              ("empty", "sni_host(b'') is None", "an empty buffer"),
              ("truncated", "sni_host(HELLO[:40]) is None", "a buffer cut short")],
             difficulty=5, points=520,
             setup=(
                 "def _client_hello(extra=b'', with_sni=True):\n"
                 "    host = b'lab.example.com'\n"
                 "    n = len(host)\n"
                 "    sni = (3 + n).to_bytes(2, 'big') + b'\\x00' + n.to_bytes(2, 'big') + host\n"
                 "    sni = b'\\x00\\x00' + len(sni).to_bytes(2, 'big') + sni if with_sni else b''\n"
                 "    exts = sni + extra\n"
                 "    body = (b'\\x03\\x03' + b'\\x00' * 32 + b'\\x00'\n"
                 "            + b'\\x00\\x02\\x13\\x01' + b'\\x01\\x00'\n"
                 "            + len(exts).to_bytes(2, 'big') + exts)\n"
                 "    hs = b'\\x01' + len(body).to_bytes(3, 'big') + body\n"
                 "    return b'\\x16\\x03\\x01' + len(hs).to_bytes(2, 'big') + hs\n\n"
                 "HELLO = _client_hello()\n"
                 "HELLO_NO_SNI = _client_hello(b'\\x00\\x2b\\x00\\x02\\x03\\x04', with_sni=False)\n"),
             area="TLS",
             hint="Offset 43 is the session-id length; from there every block is a length field followed by that many bytes."),

    sec_task("net2-jwt-expiry", "Reject an expired token",
             "Complete `is_expired` so it reads the `exp` claim and reports whether the token is "
             "already past it. A token without `exp` is treated as expired — an unbounded token "
             "is a permanent credential, and a rejected clock skew is a denial of service you can "
             "avoid with a 30-second window.",
             "import json, base64, time\n\ndef is_expired(token, now=None):\n    ...\n",
             "import base64, json, time\n\n"
             "def is_expired(token, now=None):\n"
             "    try:\n"
             "        part = token.split('.')[1]\n"
             "        claims = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))\n"
             "        exp = claims.get('exp')\n"
             "        if exp is None:\n"
             "            return True\n"
             "        return (now if now is not None else time.time()) >= float(exp)\n"
             "    except Exception:\n"
             "        return True\n",
             [("past", "is_expired(TOKEN, 999999999) is True", "clock after exp"),
              ("future", "is_expired(TOKEN, 0) is False", "clock before exp"),
              ("no exp claim", "is_expired('eyJzdWIiOiIxIn0.x.y', 0) is True", "a token without exp"),
              ("garbage", "is_expired('nope', 0) is True", "not a token at all")],
             difficulty=3, points=230, setup="import base64, json, time\nTOKEN = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiZXhwIjoxNTAwMDB9.c2ln'\n",
             area="TLS",
             hint="Decode the middle part, then `claims.get('exp')` — and decide what a missing claim means on purpose."),

    sec_task("net2-cors", "Read a CORS preflight answer",
             "Complete `allows_origin` so it returns `True` only when the response echoes the "
             "request's origin, or carries the literal `*`. Reflecting an arbitrary origin with "
             "`Access-Control-Allow-Origin` set from the request is the classic CORS mistake — it "
             "defeats the same-origin policy completely.",
             "def allows_origin(header, request_origin):\n    ...\n",
             "def allows_origin(header, request_origin):\n"
             "    h = str(header or '').strip()\n"
             "    o = str(request_origin or '').strip()\n"
             "    if h == '*':\n"
             "        return True\n"
             "    if not o or h != o:\n"
             "        return False\n"
             "    return 'null' not in o\n",
             [("exact match", "allows_origin('https://a.pl', 'https://a.pl') is True", "a matching origin"),
              ("wildcard", "allows_origin('*', 'https://evil.example') is True", "a wildcard header"),
              ("mismatch", "allows_origin('https://a.pl', 'https://evil.example') is False", "two different origins"),
              ("null origin refused", "allows_origin('null', 'null') is False", "the null origin"),
              ("missing header", "allows_origin('', 'https://a.pl') is False", "no header at all")],
             difficulty=2, points=160, area="HTTP",
             hint="Compare strings exactly; the `null` origin is the one case where a literal match still must fail."),

    sec_task("net2-cookie-flags", "Spot the flags a cookie is missing",
             "Complete `weaknesses` so it returns the names of the attributes a `Set-Cookie` value "
             "is **missing**: `Secure`, `HttpOnly` and `SameSite`. An empty list means the cookie "
             "is fine. This is the check a security review runs on every session cookie.",
             "def weaknesses(set_cookie):\n    ...\n",
             "def weaknesses(set_cookie):\n"
             "    v = str(set_cookie or '').lower()\n"
             "    out = []\n"
             "    if 'secure' not in v:\n"
             "        out.append('Secure')\n"
             "    if 'httponly' not in v:\n"
             "        out.append('HttpOnly')\n"
             "    if 'samesite' not in v:\n"
             "        out.append('SameSite')\n"
             "    return out\n",
             [("all three present", "weaknesses('a=1; Secure; HttpOnly; SameSite=Lax') == []", "a complete cookie"),
              ("nothing set", "weaknesses('a=1') == ['Secure', 'HttpOnly', 'SameSite']", "a bare cookie"),
              ("one missing", "weaknesses('a=1; Secure; HttpOnly') == ['SameSite']", "SameSite missing"),
              ("empty value", "weaknesses('') == ['Secure', 'HttpOnly', 'SameSite']", "an empty header")],
             difficulty=2, points=110, area="HTTP",
             hint="Lowercase once, then three independent `not in` checks appended to a list."),

    sec_task("net2-ssrf-redirect", "Follow a redirect without leaving the scope",
             "Complete `in_scope` so it reports whether a URL's host is inside the allowed domain "
             "**after** the scheme, userinfo and port have been taken apart. A check that runs on "
             "the raw string is bypassed by `http://allowed.pl@evil.example/`.",
             "from urllib.parse import urlsplit\n\ndef in_scope(url, allowed):\n    ...\n",
             "from urllib.parse import urlsplit\n\n"
             "def in_scope(url, allowed):\n"
             "    try:\n"
             "        p = urlsplit(str(url or ''))\n"
             "        host = (p.hostname or '').lower()\n"
             "        if p.scheme not in ('http', 'https') or not host:\n"
             "            return False\n"
             "        return host == allowed or host.endswith('.' + allowed)\n"
             "    except ValueError:\n"
             "        return False\n",
             [("apex", "in_scope('https://a.pl/x', 'a.pl') is True", "the domain itself"),
              ("subdomain", "in_scope('https://cdn.a.pl/x', 'a.pl') is True", "a subdomain"),
              ("other domain", "in_scope('https://evil.example/', 'a.pl') is False", "somebody else's domain"),
              ("suffix trick", "in_scope('https://nota.pl/x', 'a.pl') is False", "a domain that merely ends in the string"),
              ("userinfo trick", "in_scope('http://a.pl@evil.example/', 'a.pl') is False", "userinfo before the real host"),
              ("non-http scheme", "in_scope('file:///etc/passwd', 'a.pl') is False", "a file URL"),
              ("garbage", "in_scope('://', 'a.pl') is False", "unparseable input")],
             difficulty=4, points=310, setup="from urllib.parse import urlsplit\n", area="HTTP",
             hint="`urlsplit(...).hostname` already strips the userinfo and lowercases — use it instead of the raw string."),

    sec_task("net2-dns-rebind", "Pin the address, not the name",
             "Complete `pinned` so it returns the addresses the hostname resolved to **once**, and "
             "a second call with a changed answer returns `None` instead of a new address. DNS "
             "rebinding works because the name is looked up again after the check passed.",
             "def pinned(host, answers, first=None):\n    ...\n",
             "def pinned(host, answers, first=None):\n"
             "    got = sorted(answers.get(host, []))\n"
             "    if first is None:\n"
             "        return got\n"
             "    return None if got != sorted(first) else got\n",
             [("first lookup", "pinned('a.pl', {'a.pl': ['10.0.0.1']}) == ['10.0.0.1']", "the first resolution"),
              ("unchanged is fine", "(lambda f: pinned('a.pl', {'a.pl': ['10.0.0.1']}, f) == ['10.0.0.1'])(pinned('a.pl', {'a.pl': ['10.0.0.1']}))", "the same answer twice"),
              ("changed is refused", "(lambda f: pinned('a.pl', {'a.pl': ['127.0.0.1']}, f) is None)(pinned('a.pl', {'a.pl': ['10.0.0.1']}))", "a different answer"),
              ("unknown host", "pinned('b.pl', {}) == []", "a host with no records")],
             difficulty=4, points=270, area="DNS",
             hint="Sort both sides, compare, and remember the first answer in the caller's variable."),

    sec_task("net2-tls-version", "Name the TLS version from the record header",
             "Complete `tls_version` so it maps the record-layer version bytes to a name, and "
             "returns `'unknown'` for anything else. The ClientHello carries the version it wants, "
             "and a middlebox that only looks at this byte is bypassable — the real check is the "
             "supported-versions extension.",
             "VERSIONS = {0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'}\n\n"
             "def tls_version(record):\n    ...\n",
             "VERSIONS = {0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'}\n\n"
             "def tls_version(record):\n"
             "    b = bytes(record or b'')\n"
             "    if len(b) < 3 or b[0] != 0x16:\n"
             "        return 'unknown'\n"
             "    return VERSIONS.get(int.from_bytes(b[1:3], 'big'), 'unknown')\n",
             [("1.2", "tls_version(bytes([0x16, 0x03, 0x03])) == 'TLS 1.2'", "0x0303"),
              ("1.3", "tls_version(bytes([0x16, 0x03, 0x04])) == 'TLS 1.3'", "0x0304"),
              ("1.0", "tls_version(bytes([0x16, 0x03, 0x01])) == 'TLS 1.0'", "0x0301"),
              ("garbage", "tls_version(bytes([0x16, 0xff, 0xff])) == 'unknown'", "0xffff"),
              ("not a handshake record", "tls_version(bytes([0x17, 0x03, 0x03])) == 'unknown'", "application data"),
              ("too short", "tls_version(b'') == 'unknown'", "an empty record")],
             difficulty=2, points=120, area="TLS",
             hint="`int.from_bytes(b[:2], 'big')` is the version; a `.get` with a default covers the rest."),

    sec_task("net2-subnet-count", "How many hosts does a network really have",
             "Complete `host_count` so it returns the number of usable addresses in a CIDR block. "
             "The network and broadcast addresses are not usable, so `/30` has two hosts and a "
             "`/32` has one. This is the number that has to fit in your address plan.",
             "def host_count(cidr):\n    ...\n",
             "def host_count(cidr):\n"
             "    bits = int(str(cidr).split('/')[1])\n"
             "    total = 1 << (32 - bits)\n"
             "    return 1 if total == 1 else total - 2\n",
             [("/24", "host_count('10.0.0.0/24') == 254", "a /24"),
              ("/30", "host_count('10.0.0.0/30') == 2", "a /30"),
              ("/32 is one host", "host_count('10.0.0.0/32') == 1", "a /32"),
              ("/16", "host_count('10.0.0.0/16') == 65534", "a /16"),
              ("/0", "host_count('0.0.0.0/0') == 4294967294", "the whole address space")],
             difficulty=2, points=130, area="Addresses",
             hint="`1 << (32 - bits)` is the total; subtract two unless the total is already one."),

    sec_task("net2-tcp-flags", "Read the flags out of a TCP header",
             "Complete `flags` so it returns the set of flag names present in a 13-byte TCP header "
             "starting at the flags byte. SYN, ACK, FIN, RST, PSH and URG are the six that matter "
             "in an incident. A SYN scan is a SYN with no ACK.",
             "def flags(header):\n    ...\n",
             "BITS = [(0x02, 'SYN'), (0x10, 'ACK'), (0x01, 'FIN'), (0x04, 'RST'), (0x08, 'PSH'), (0x20, 'URG')]\n\n"
             "def flags(header):\n"
             "    b = bytes(header or b'')\n"
             "    if len(b) < 14:\n"
             "        return set()\n"
             "    return {name for bit, name in BITS if b[13] & bit}\n",
             [("syn", "flags(bytes(13) + bytes([0x02])) == {'SYN'}", "a SYN"),
              ("syn ack", "flags(bytes(13) + bytes([0x12])) == {'SYN', 'ACK'}", "a SYN-ACK"),
              ("fin ack", "flags(bytes(13) + bytes([0x11])) == {'FIN', 'ACK'}", "a FIN-ACK"),
              ("nothing", "flags(bytes(13) + bytes([0x00])) == set()", "no flags set"),
              ("short header", "flags(b'') == set()", "a truncated header")],
             difficulty=3, points=210, area="Transport",
             hint="Bit 13 of the header is the flags byte; `b[13] & bit` tests one flag at a time."),
]

NET_PY = [
    py_task("py2-urlparse", "Pull the parts out of a URL",
            "Complete `describe` so it returns `(scheme, host, port, path)` from a URL, defaulting "
            "the port by scheme — 443 for https, 80 otherwise. `urlsplit(...).port` raises on a "
            "non-numeric port, so you have to catch it: a malformed URL is input, not an exception.",
            "from urllib.parse import urlsplit\n\ndef describe(url):\n    ...\n",
            "from urllib.parse import urlsplit\n\n"
            "def describe(url):\n"
            "    try:\n"
            "        p = urlsplit(str(url or ''))\n"
            "        port = p.port\n"
            "    except ValueError:\n"
            "        return None\n"
            "    scheme = (p.scheme or '').lower()\n"
            "    port = port or (443 if scheme == 'https' else 80 if scheme == 'http' else None)\n"
            "    return scheme, (p.hostname or '').lower(), port, p.path or '/'\n",
            [("https", "describe('https://a.pl/x') == ('https', 'a.pl', 443, '/x')", "https with a path"),
             ("http default", "describe('http://a.pl') == ('http', 'a.pl', 80, '/')", "http with no path"),
             ("explicit port", "describe('https://a.pl:8443/') == ('https', 'a.pl', 8443, '/')", "an explicit port"),
             ("bad port", "describe('https://a.pl:x/') is None", "a non-numeric port"),
             ("empty path", "describe('https://a.pl') == ('https', 'a.pl', 443, '/')", "no path at all")],
            difficulty=2, points=150, area="URLs",
            hint="`p.port` raises `ValueError` for junk — wrap just that access in `try`."),

    py_task("py2-query-string", "Read query parameters without a framework",
            "Complete `params` so it returns a dict of query parameters, later values winning and "
            "an empty value becoming `''`. `parse_qs` gives you lists; most callers want the last "
            "one. Percent-decoding is already done for you by the parser.",
            "from urllib.parse import urlsplit, parse_qsl\n\ndef params(url):\n    ...\n",
            "from urllib.parse import parse_qsl, urlsplit\n\n"
            "def params(url):\n"
            "    return {k: v for k, v in parse_qsl(urlsplit(str(url or '')).query, keep_blank_values=True)}\n",
            [("one param", "params('/x?a=1') == {'a': '1'}", "one parameter"),
             ("two params", "params('/x?a=1&b=2') == {'a': '1', 'b': '2'}", "two parameters"),
             ("decoded", "params('/x?q=a%20b') == {'q': 'a b'}", "a percent-encoded value"),
             ("empty value", "params('/x?a=') == {'a': ''}", "a blank value"),
             ("no query", "params('/x') == {}", "no query string"),
             ("plus is a space", "params('/x?q=a+b') == {'q': 'a b'}", "a plus-encoded space")],
            difficulty=2, points=120, area="URLs",
            hint="`parse_qsl(..., keep_blank_values=True)` then a dict comprehension does the whole job."),

    py_task("py2-cookie-jar", "Parse a cookie header into a dict",
            "Complete `cookies` so it returns a dict from a `Cookie:` header value, trimming the "
            "spaces and ignoring a pair with no `=`. A duplicate name keeps the **last** value, "
            "which is how a later Set-Cookie overrides an earlier one.",
            "def cookies(header):\n    ...\n",
            "def cookies(header):\n"
            "    out = {}\n"
            "    for part in str(header or '').split(';'):\n"
            "        part = part.strip()\n"
            "        if '=' not in part:\n"
            "            continue\n"
            "        k, _, v = part.partition('=')\n"
            "        k = k.strip()\n"
            "        if k:\n"
            "            out[k] = v.strip()\n"
            "    return out\n",
            [("one pair", "cookies('a=1') == {'a': '1'}", "a single pair"),
             ("three pairs", "cookies('a=1; b=2; c=3') == {'a': '1', 'b': '2', 'c': '3'}", "three pairs"),
             ("spaces trimmed", "cookies(' a = 1 ; b = 2 ') == {'a': '1', 'b': '2'}", "loose spacing"),
             ("junk skipped", "cookies('a=1; junk; b=2') == {'a': '1', 'b': '2'}", "a pair with no equals"),
             ("last wins", "cookies('a=1; a=2') == {'a': '2'}", "a repeated name"),
             ("empty", "cookies('') == {}", "an empty header")],
            difficulty=2, points=110, area="HTTP",
            hint="Split on `;`, `partition('=')`, and skip anything without the separator."),

    py_task("py2-time-window", "Count requests in a sliding window",
            "Complete `recent` so it returns how many timestamps in `stamps` fall inside the last "
            "`window` seconds **relative to each timestamp**, not to now. Timestamps need not be "
            "sorted; an empty list is 0. This is the core of every rate limiter and every "
            "\"suspicious burst\" detector.",
            "def recent(stamps, window):\n    ...\n",
            "def recent(stamps, window):\n"
            "    s = sorted(stamps)\n"
            "    out = []\n"
            "    for i, t in enumerate(s):\n"
            "        out.append(sum(1 for u in s[:i + 1] if t - u < window))\n"
            "    return out\n",
            [("two in window", "recent([0, 5, 20], 10) == [1, 2, 1]", "a burst then a gap"),
             ("all outside", "recent([0, 100, 200], 10) == [1, 1, 1]", "widely spaced"),
             ("boundary excluded", "recent([0, 10], 10) == [1, 1]", "exactly at the window edge"),
             ("single stamp", "recent([5], 10) == [1]", "one timestamp"),
             ("empty", "recent([], 10) == []", "no timestamps")],
            difficulty=4, points=290, area="Traffic",
            hint="Sort first, then for each position count how many of the stamps up to it are inside the window."),

    py_task("py2-p95", "The 95th percentile, nearest-rank",
            "Complete `p95` so it returns the value at the 95th percentile using the nearest-rank "
            "method: sort, then take index `ceil(0.95 * n) - 1`. An empty list gives `None`. A "
            "mean would be useless here — one slow request should dominate the way it does in "
            "reality.",
            "def p95(values):\n    ...\n",
            "import math\n\ndef p95(values):\n"
            "    if not values:\n"
            "        return None\n"
            "    s = sorted(values)\n"
            "    return s[max(0, math.ceil(0.95 * len(s)) - 1)]\n",
            [("simple", "p95([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) == 10", "ten values"),
             ("outlier dominates", "p95([1, 2, 3, 4, 5, 6, 7, 8, 9, 1000]) == 1000", "nine fast, one very slow"),
             ("single value", "p95([42]) == 42", "one value"),
             ("empty", "p95([]) is None", "no values")],
            difficulty=2, points=120, area="Traffic",
            hint="`math.ceil(0.95 * n) - 1` is the 0-based index; guard it with `max(0, ...)`."),

    py_task("py2-topk", "The k heaviest requests, ties broken by order",
            "Complete `heaviest` so it returns the k largest values, largest first, and ties keep "
            "their **original** order. `sorted(..., reverse=True)` is stable, which is exactly the "
            "property you want. This is what a slow-query log is really asking for.",
            "def heaviest(values, k):\n    ...\n",
            "def heaviest(values, k):\n"
            "    if k <= 0:\n"
            "        return []\n"
            "    return sorted(values, reverse=True)[:k]\n",
            [("top two", "heaviest([1, 5, 3], 2) == [5, 3]", "the two largest"),
             ("k above length", "heaviest([1, 2], 5) == [2, 1]", "more than there is"),
             ("k zero", "heaviest([1, 2], 0) == []", "k of zero"),
             ("ties keep order", "heaviest([7, 2, 7, 9], 2) == [9, 7]", "two equal values"),
             ("empty", "heaviest([], 3) == []", "no values")],
            difficulty=2, points=90, area="Traffic",
            hint="`sorted` is stable, so `reverse=True` keeps the original order inside a group of equals."),

    py_task("py2-dedupe-window", "Drop repeats inside a time window",
            "Complete `dedupe_window` so it keeps the first occurrence of each value and drops a "
            "later repeat that arrives within `window` seconds. A repeat **after** the window is "
            "kept — that is a real second event, not a duplicate.",
            "def dedupe_window(events, window):\n    ...\n",
            "def dedupe_window(events, window):\n"
            "    last = {}\n"
            "    out = []\n"
            "    for t, key in events:\n"
            "        if key in last and t - last[key] < window:\n"
            "            continue\n"
            "        last[key] = t\n"
            "        out.append((t, key))\n"
            "    return out\n",
            [("inside the window", "dedupe_window([(0, 'a'), (5, 'a')], 10) == [(0, 'a')]", "a repeat five seconds later"),
             ("outside the window", "dedupe_window([(0, 'a'), (20, 'a')], 10) == [(0, 'a'), (20, 'a')]", "a repeat after the window"),
             ("boundary excluded", "dedupe_window([(0, 'a'), (10, 'a')], 10) == [(0, 'a'), (10, 'a')]", "exactly at the edge"),
             ("different keys", "dedupe_window([(0, 'a'), (1, 'b')], 10) == [(0, 'a'), (1, 'b')]", "two different keys"),
             ("empty", "dedupe_window([], 10) == []", "no events")],
            difficulty=3, points=200, area="Traffic",
            hint="A dict of key → last seen timestamp; skip when `t - last[key] < window`."),
]

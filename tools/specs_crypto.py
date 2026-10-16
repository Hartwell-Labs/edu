#!/usr/bin/env python3
"""specs_crypto.py — kryptografia, kodowanie, sieć i bezpieczne API (Pyodide)."""
from gen_tasks import crypto_task, net_task

CRYPTO = []
NET = []

# ---------------------------------------------------------------- kryptografia / kodowanie
CRYPTO += [
    crypto_task(
        "cry-sha256-verify", "Verify a downloaded artifact",
        "You have file bytes and a published digest. Complete `verify` so it compares the two "
        "with `hmac.compare_digest` and returns `True` only when they match.\n\n"
        "**Stretch:** what happens when the two hex strings differ only in case? Make the answer "
        "independent of how the publisher wrote it.",
        "import hashlib, hmac\n\nDATA = b'anvil-lab'\nEXPECTED = '621824640ff85d4bfab5a9092831b8674de5d14b0f1e9c5532e3fb8410f469f0'\n\ndef verify(data, expected):\n    ...\n",
        "import hashlib, hmac\n\ndef verify(data, expected):\n    got = hashlib.sha256(data).hexdigest()\n    return hmac.compare_digest(got, expected.lower())\n",
        [("the published digest matches", "verify(DATA, EXPECTED) is True", "verify(DATA, EXPECTED)"),
         ("a tampered file fails", "verify(DATA + b'x', EXPECTED) is False"),
         ("wrong length fails", "verify(b'', 'abc') is False"),
         ("empty file has a digest", "verify(b'', hashlib.sha256(b'').hexdigest()) is True"),
         ("case insensitive", "verify(DATA, EXPECTED.upper()) is True", "verify(DATA, EXPECTED.upper())")],
        ["`hmac.compare_digest` is the only comparison that does not leak timing.",
         "Compare the hex strings, never the bytes-to-int shortcut.",
         "`compare_digest` needs two `str` of ASCII **or** two bytes-like objects — mixing them raises."],
        setup="import hashlib, hmac\nDATA = b'anvil-lab'\nEXPECTED = '621824640ff85d4bfab5a9092831b8674de5d14b0f1e9c5532e3fb8410f469f0'\n",
        stretch="Return a tuple `(ok, computed)` so the log shows what you expected to see."),

    crypto_task(
        "cry-base64url-jwt", "Decode a JWT payload safely",
        "A JWT is three base64**url** parts. Complete `payload` so it returns the claims dict, "
        "and `unsigned` so it reports a header with `alg: none`. base64url uses `-`/`_` and drops "
        "`=` padding — put the padding back before decoding. Malformed input gives `None`.\n\n"
        "**Stretch:** add `header()` and reject anything whose `alg` is not in an allow-list.",
        "import base64, json\n\nTOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4ifQ.c2ln'\nNONE_TOKEN = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.'\n\ndef payload(token):\n    ...\n\ndef unsigned(token):\n    ...\n",
        "import base64, json\n\ndef _part(p):\n    return base64.urlsafe_b64decode(p + '=' * (-len(p) % 4))\n\ndef payload(token):\n    parts = token.split('.')\n    if len(parts) < 2:\n        return None\n    try:\n        return json.loads(_part(parts[1]))\n    except Exception:\n        return None\n\ndef unsigned(token):\n    parts = token.split('.')\n    if not parts or not parts[0]:\n        return False\n    try:\n        return json.loads(_part(parts[0])).get('alg') == 'none'\n    except Exception:\n        return False\n",
        [("claims decode", "payload(TOKEN) == {'sub': '123', 'role': 'admin'}", "payload(TOKEN)"),
         ("garbage is None", "payload('nope') is None", "payload('nope')"),
         ("too few parts", "payload('a.b') is None", "payload('a.b')"),
         ("alg none", "unsigned(NONE_TOKEN) is True", "unsigned(NONE_TOKEN)"),
         ("signed token", "unsigned(TOKEN) is False", "unsigned(TOKEN)"),
         ("empty token", "unsigned('') is False", "unsigned('')")],
        ["Padding: `'=' * (-len(part) % 4)` adds 0–3 characters.",
         "`alg` lives in the **header** (first part), not the payload.",
         "Decoding is not verifying — never trust claims before checking the signature."],
        setup="import base64, json\n"
        "TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4ifQ.c2ln'\n"
        "NONE_TOKEN = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.'\n",
        stretch="Refuse `alg: none` *and* every asymmetric algorithm your service does not expect."),

    crypto_task(
        "cry-hexdump", "Turn a hexdump back into bytes",
        "You get a `xxd`-style hexdump. Complete `parse_hexdump` so it returns the raw bytes, "
        "ignoring the offset, the hex columns and the ASCII gutter. Lines with no hex digits "
        "(the trailing offset line) are skipped.\n\n"
        "**Stretch:** return the printable ASCII gutter alongside the bytes.",
        "DUMP = '''00000000: 616e 7669 6c2d 6c61 6220 7461 736b  anvil-lab task\n00000010: 2064 6f6e 6521                                 done!\n'''\n",
        "def parse_hexdump(dump):\n"
        "    out = bytearray()\n"
        "    for line in dump.splitlines():\n"
        "        parts = line.split(':')\n"
        "        if len(parts) < 2:\n"
        "            continue\n"
        "        hexpart = parts[1].split('  ')[0]\n"
        "        for pair in hexpart.split():\n"
        "            if len(pair) == 4 and all(c in '0123456789abcdefABCDEF' for c in pair):\n"
        "                out += bytes.fromhex(pair)\n"
        "    return bytes(out)\n",
        [("full payload", "parse_hexdump(DUMP).startswith(b'anvil-lab task')", "parse_hexdump(DUMP)[:20]"),
         ("both lines merged", "parse_hexdump(DUMP) == b'anvil-lab task done!'", "parse_hexdump(DUMP)"),
         ("the last offset line is skipped", "parse_hexdump(DUMP + '\\n00000020\\n').endswith(b'done!')"),
         ("empty dump", "parse_hexdump('') == b''", "parse_hexdump('')")],
        ["Split on `:` first: everything before it is the offset.",
         "Two spaces separate the hex block from the ASCII gutter — `split('  ')[0]`.",
         "`all(c in hexdigits ...)` is what keeps the offset line from being decoded as hex."],
        setup="DUMP = '''00000000: 616e 7669 6c2d 6c61 6220 7461 736b  anvil-lab task\n00000010: 2064 6f6e 6521                                 done!\n'''\n",
        stretch="`bytes.fromhex` ignores spaces — you may not need the pair loop at all."),

    crypto_task(
        "cry-caesar", "Shift letters without losing the rest",
        "Complete `caesar` so it shifts ASCII letters by `n` and leaves everything else — "
        "digits, punctuation, spaces — exactly where it is. Wrapping is circular: `a` shifted "
        "by 1 is `b`, `z` by 1 is `a`, and negative shifts work too.\n\n"
        "**Stretch:** apply it to a whole sentence, and make it raise for a shift outside 0–25.",
        "def caesar(text, n):\n    ...\n",
        "def caesar(text, n):\n    out = []\n    for ch in text:\n        if 'a' <= ch <= 'z':\n            out.append(chr((ord(ch) - 97 + n) % 26 + 97))\n        elif 'A' <= ch <= 'Z':\n            out.append(chr((ord(ch) - 65 + n) % 26 + 65))\n        else:\n            out.append(ch)\n    return ''.join(out)\n",
        [("simple shift", "caesar('abc', 1) == 'bcd'", "caesar('abc', 1)"),
         ("wraps around", "caesar('xyz', 3) == 'abc'", "caesar('xyz', 3)"),
         ("digits stay", "caesar('anvil-123!', 1) == 'bowjm-123!'", "caesar('anvil-123!', 1)"),
         ("negative shift", "caesar('bcd', -1) == 'abc'", "caesar('bcd', -1)"),
         ("case preserved", "caesar('Anvil', 1) == 'Bowjm'", "caesar('Anvil', 1)"),
         ("empty", "caesar('', 5) == ''", "caesar('', 5)")],
        ["`% 26` is the whole wrap-around trick.",
         "`ord(ch) - 97` turns a letter into 0–25, and you add 97 to go back.",
         "Two branches for case, or one if you compute `base = 65 if ch.isupper() else 97`."],
        stretch="This is the toy version of a real cipher — Caesar is broken, ROT13 is obfuscation."),

    crypto_task(
        "cry-xor", "XOR two byte strings of different lengths",
        "Complete `xor_bytes` so it returns the byte-wise XOR, **repeating the shorter key**. "
        "That is what a stream cipher effectively does, and it is why a reused key gives the key "
        "away: `c ^ c == 0`.\n\n"
        "**Stretch:** given ciphertext and plaintext of the same length, recover the key.",
        "def xor_bytes(data, key):\n    ...\n",
        "def xor_bytes(data, key):\n    if not key:\n        return bytes(data)\n"
        "    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))\n",
        [("single byte key", "xor_bytes(b'\\x0f\\x0e\\x0d', b'\\x01') == b'\\x0e\\x0f\\x0c'", "xor_bytes(b'\\x0f\\x0e\\x0d', b'\\x01')"),
         ("repeated key", "xor_bytes(b'abcd', b'xy') == b'\\x19\\x1b\\x1b\\x1d'", "xor_bytes(b'abcd', b'xy')"),
         ("identity", "xor_bytes(b'hello', b'') == b'hello'", "xor_bytes(b'hello', b'')"),
         ("xoring twice is identity", "xor_bytes(xor_bytes(b'secret', b'k'), b'k') == b'secret'"),
         ("null key", "xor_bytes(b'abc', b'\\x00') == b'abc'", "xor_bytes(b'abc', b'\\x00')")],
        ["`enumerate` plus `key[i % len(key)]` gives you the repeating key.",
         "`bytes(generator)` works — the comprehension yields ints in 0–255.",
         "Check `if not key` first: `% 0` raises `ZeroDivisionError`."],
        stretch="Recover a key from known plaintext: `key = c ^ p` for each position."),

    crypto_task(
        "cry-entropy", "Estimate how much randomness a string has",
        "Complete `shannon_bits` so it returns the Shannon entropy **per character** in bits "
        "(0 for `aaaa`, 1 for `abab`). A password with 3.5 bits per character is a coin flip per "
        "character — that is what you tell a user who thinks `Password1!` is strong.\n\n"
        "**Stretch:** return the estimated search space as a number of candidates.",
        "import math\nfrom collections import Counter\n\ndef shannon_bits(text):\n    ...\n",
        "import math\nfrom collections import Counter\n\ndef shannon_bits(text):\n    if not text:\n        return 0.0\n    counts = Counter(text)\n    n = len(text)\n    return -sum((c / n) * math.log2(c / n) for c in counts.values())\n",
        [("one symbol", "shannon_bits('aaaa') == 0.0", "shannon_bits('aaaa')"),
         ("two symbols evenly", "abs(shannon_bits('abab') - 1.0) < 1e-9", "shannon_bits('abab')"),
         ("empty string", "shannon_bits('') == 0.0", "shannon_bits('')"),
         ("single char", "shannon_bits('a') == 0.0", "shannon_bits('a')"),
         ("mixed beats repetition", "shannon_bits('aabbccdd') > shannon_bits('aaaabbbb')", "shannon_bits('aabbccdd')")],
        ["Entropy is `sum(-p * log2(p))` over the symbol counts.",
         "`Counter` gives you the counts; the total is `len(text)`.",
         "Guard the empty string: the sum over no symbols is 0 anyway, but be explicit."],
        stretch="Multiply by the length for total bits — that is the number of guesses."),

    crypto_task(
        "cry-password-check", "Score a password without storing it",
        "Complete `score` so it returns 0–4: length, both cases, digits, symbols. The point of the "
        "lab is the return value — a real service never keeps the password, only this score plus "
        "a stretched hash.\n\n"
        "**Stretch:** reject anything from the ten most common passwords outright, and say so.",
        "COMMON = {'password', '123456', 'qwerty', 'letmein', 'admin'}\n\ndef score(pw):\n    ...\n",
        "COMMON = {'password', '123456', 'qwerty', 'letmein', 'admin'}\n\ndef score(pw):\n"
        "    s = 0\n"
        "    if len(pw) >= 12: s += 2\n"
        "    elif len(pw) >= 8: s += 1\n"
        "    if any(c.islower() for c in pw) and any(c.isupper() for c in pw): s += 1\n"
        "    if any(c.isdigit() for c in pw): s += 1\n"
        "    if any(not c.isalnum() for c in pw): s += 1\n"
        "    return min(4, s)\n",
        [("long and complex", "score('Anvil-Lab-2026!x') >= 4", "score('Anvil-Lab-2026!x')"),
         ("short simple", "score('abc') <= 1", "score('abc')"),
         ("length matters", "score('aaaaaaaaaaaa') > score('aaaa')", "score('aaaaaaaaaaaa')"),
         ("digits help", "score('abcdefgh1234') > score('abcdefgh')", "score('abcdefgh1234')"),
         ("never above four", "score('aB3$aB3$aB3$aB3$') == 4", "score('aB3$aB3$aB3$aB3$')")],
        ["Cap the result with `min(4, s)` — a score above the scale is a bug waiting to happen.",
         "`any()` over a generator expression reads better than four `if`s.",
         "Length is worth two points here; it is the only factor that really matters."],
        stretch="Length beats character classes: compare this scorer against a pure-length one."),

    crypto_task(
        "cry-pkcs7", "Pad and unpad a block by hand",
        "Complete `pad` and `unpad` for PKCS#7. Padding always adds 1–16 bytes, so `unpad` never "
        "sees a full block unchanged — and it must **reject** a bad padding byte instead of "
        "returning garbage.\n\n"
        "**Stretch:** return `None` for invalid padding and make `pad` raise on a block over 16 bytes.",
        "def pad(data, block=16):\n    ...\n\ndef unpad(data):\n    ...\n",
        "def pad(data, block=16):\n    if len(data) > block:\n        raise ValueError('block too large')\n"
        "    n = block - (len(data) % block) or block\n    return data + bytes([n]) * n\n\n"
        "def unpad(data):\n    if not data:\n        return None\n"
        "    n = data[-1]\n"
        "    if n < 1 or n > len(data):\n        return None\n"
        "    if data[-n:] != bytes([n]) * n:\n        return None\n"
        "    return data[:-n]\n",
        [("round trip", "unpad(pad(b'hello')) == b'hello'", "unpad(pad(b'hello'))"),
         ("pads to a full block", "len(pad(b'hello')) == 16", "len(pad(b'hello'))"),
         ("a full block gets a whole new one", "len(pad(b'x' * 16)) == 32", "len(pad(b'x' * 16))"),
         ("empty input", "unpad(b'') is None", "unpad(b'')"),
         ("bad padding rejected", "unpad(b'abc\\x05\\x05') is None", "unpad(b'abc\\x05\\x05')"),
         ("impossible length rejected", "unpad(b'abc\\xff') is None", "unpad(b'abc\\xff')")],
        ["PKCS#7 always adds at least one byte, even when the input is already aligned.",
         "`data[-n:] != bytes([n]) * n` checks the whole padding run, not just the last byte.",
         "Return `None` on bad padding — raising on attacker-controlled bytes is a denial of service."],
        stretch="Timing matters: this comparison is not constant-time."),

    crypto_task(
        "cry-cert-expiry", "Parse a certificate validity window",
        "Complete `expires_within` so it parses two ISO-8601 timestamps and returns the number of "
        "days between them, or `None` if the end is not after the start. A certificate that "
        "expires in the past is worse than no certificate.\n\n"
        "**Stretch:** flag anything expiring in under 30 days.",
        "from datetime import datetime\n\ndef expires_within(start, end):\n    ...\n",
        "from datetime import datetime\n\ndef expires_within(start, end):\n"
        "    a = datetime.fromisoformat(start)\n"
        "    b = datetime.fromisoformat(end)\n"
        "    if b <= a:\n        return None\n"
        "    return (b - a).days\n",
        [("a normal year", "expires_within('2026-01-01T00:00:00', '2027-01-01T00:00:00') == 365",
          "expires_within('2026-01-01T00:00:00', '2027-01-01T00:00:00')"),
         ("the same instant", "expires_within('2026-01-01', '2026-01-01') is None", "expires_within('2026-01-01', '2026-01-01')"),
         ("end before start", "expires_within('2026-02-01', '2026-01-01') is None", "expires_within('2026-02-01', '2026-01-01')"),
         ("already expired", "expires_within('2025-01-01', '2026-01-01') == 365", "expires_within('2025-01-01', '2026-01-01')")],
        ["`datetime.fromisoformat` in Python 3.11+ parses both dates and timestamps.",
         "`timedelta.days` truncates — that is the honest number of whole days.",
         "`b <= a` catches both the zero window and the impossible one."],
        stretch="Add a hard cutoff: `None` when fewer than 30 days remain."),
]

# ----------------------------------------------------------------------- sieć
NET += [
    net_task(
        "net-cidr-contains", "Check whether an address is inside a CIDR block",
        "Complete `in_cidr(ip, cidr)` so it works for IPv4 without any library: split the network "
        "and the address into octets, convert with `int(octet, 2 ** 8 * n)`, and compare "
        "against the masked network.\n\n"
        "**Stretch:** accept a list of blocks — `in_any(ip, ['10.0.0.0/8', '192.168.0.0/16'])`, "
        "which is how firewall rules are written.",
        "def in_cidr(ip, cidr):\n    ...\n",
        "def in_cidr(ip, cidr):\n    net, _, bits = cidr.partition('/')\n    prefix = int(bits)\n"
        "    n = [int(o) for o in net.split('.')]\n    a = [int(o) for o in ip.split('.')]\n"
        "    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF\n"
        "    return (sum(n[i] << (24 - 8 * i) for i in range(4)) & mask) == \\\n"
        "           (sum(a[i] << (24 - 8 * i) for i in range(4)) & mask)\n",
        [("inside /24", "in_cidr('10.0.0.5', '10.0.0.0/24') is True", "in_cidr('10.0.0.5', '10.0.0.0/24')"),
         ("outside /24", "in_cidr('10.0.1.5', '10.0.0.0/24') is False", "in_cidr('10.0.1.5', '10.0.0.0/24')"),
         ("inside /8", "in_cidr('10.9.9.9', '10.0.0.0/8') is True", "in_cidr('10.9.9.9', '10.0.0.0/8')"),
         ("outside /8", "in_cidr('11.0.0.1', '10.0.0.0/8') is False", "in_cidr('11.0.0.1', '10.0.0.0/8')"),
         ("a /32 is one address", "in_cidr('10.0.0.7', '10.0.0.7/32') is True", "in_cidr('10.0.0.7', '10.0.0.7/32')")],
        ["Convert an address to an integer with `sum(octet << (24 - 8 * i))`.",
         "The mask for `/prefix` is `(0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF`.",
         "Compare both sides **masked** — otherwise the host bits differ and the answer is always false."],
        stretch="`in_any` over a list of CIDRs is the shape a firewall rule needs."),

    net_task(
        "net-host-count", "How many addresses does a block hold",
        "Complete `host_count` so it returns the number of usable host addresses in a CIDR block "
        "and `None` for a prefix outside 0–32. A `/31` has no usable host in classic IPv4 "
        "routing — it is a point-to-point link.\n\n"
        "**Stretch:** return the network address too.",
        "def host_count(cidr):\n    ...\n",
        "def host_count(cidr):\n    _, _, bits = cidr.partition('/')\n    prefix = int(bits)\n"
        "    if prefix < 0 or prefix > 32:\n        return None\n"
        "    total = 2 ** (32 - prefix)\n"
        "    if prefix >= 31:\n        return 0\n"
        "    return total - 2\n",
        [("a /24", "host_count('10.0.0.0/24') == 254", "host_count('10.0.0.0/24')"),
         ("a /30", "host_count('10.0.0.0/30') == 2", "host_count('10.0.0.0/30')"),
         ("a /31 has none", "host_count('10.0.0.0/31') == 0", "host_count('10.0.0.0/31')"),
         ("a /32 has none", "host_count('10.0.0.1/32') == 0", "host_count('10.0.0.1/32')"),
         ("nonsense prefix", "host_count('10.0.0.0/33') is None", "host_count('10.0.0.0/33')")],
        ["Total addresses is `2 ** (32 - prefix)`; subtract network and broadcast.",
         "`/31` and `/32` are the special cases where the answer is 0.",
         "Validate the prefix **before** computing — `2 ** -1` raises `ValueError`."],
        stretch="Modern practice treats /31 as two usable addresses on a point-to-point link."),

    net_task(
        "net-port-range", "Parse a port range from a config",
        "Config files write ports as `8080`, `8000-8100` or `8000 - 8100` with stray spaces. "
        "Complete `parse_ports` so it returns a sorted list of every port in the expression, and "
        "`None` when the range runs backwards or a port is out of 1–65535.\n\n"
        "**Stretch:** return `(low, high)` tuples instead of expanding.",
        "def parse_ports(spec):\n    ...\n",
        "def parse_ports(spec):\n"
        "    tokens = spec.replace(',', ' ').replace('-', ' - ').split()\n"
        "    out = set()\n"
        "    i = 0\n"
        "    while i < len(tokens):\n"
        "        if not tokens[i].isdigit():\n"
        "            return None\n"
        "        low = int(tokens[i])\n"
        "        if i + 1 < len(tokens) and tokens[i + 1] == '-':\n"
        "            if i + 2 >= len(tokens) or not tokens[i + 2].isdigit():\n"
        "                return None\n"
        "            high = int(tokens[i + 2])\n"
        "            i += 3\n"
        "        else:\n"
        "            high = low\n"
        "            i += 1\n"
        "        if low > high or low < 1 or high > 65535:\n"
        "            return None\n"
        "        out.update(range(low, high + 1))\n"
        "    return sorted(out)\n",
        [("single port", "parse_ports('8080') == [8080]", "parse_ports('8080')"),
         ("a range", "parse_ports('8000-8002') == [8000, 8001, 8002]", "parse_ports('8000-8002')"),
         ("spaces around the dash", "parse_ports('8000 - 8001') == [8000, 8001]", "parse_ports('8000 - 8001')"),
         ("a list", "parse_ports('22, 80, 443') == [22, 80, 443]", "parse_ports('22, 80, 443')"),
         ("backwards range", "parse_ports('8100-8000') is None", "parse_ports('8100-8000')"),
         ("out of range port", "parse_ports('70000') is None", "parse_ports('70000')")],
        ["Replace commas with spaces, then split — one code path for both syntaxes.",
         "`range(low, high + 1)` is inclusive; forgetting the `+ 1` silently drops a port.",
         "Return `None` for an impossible range instead of an empty list — they mean different things."],
        stretch="`return [(low, high)]` avoids expanding a range of 60 000 ports."),

    net_task(
        "net-host-header", "Parse a Host header without trusting it",
        "`Host: lab-a.internal:8443` may or may not carry a port, and `evil.com@lab-a.internal` "
        "is a classic parser-confusion trick. Complete `parse_host` so it returns "
        "`(hostname, port)` with the port defaulting to `None`, and returns `None` when the "
        "value contains anything unexpected.\n\n"
        "**Stretch:** return `None` for an IPv6 literal unless it is bracketed.",
        "def parse_host(value):\n    ...\n",
        "def parse_host(value):\n    value = value.strip()\n    if not value or any(c in value for c in '@ /\\\\'):\n        return None\n"
        "    if value.startswith('['):\n"
        "        end = value.find(']')\n        if end == -1:\n            return None\n"
        "        host = value[1:end]\n"
        "        rest = value[end + 1:]\n"
        "        if not rest:\n            return host, None\n"
        "        if not rest.startswith(':'):\n            return None\n"
        "        return host, int(rest[1:])\n"
        "    if value.count(':') > 1:\n        return None\n"
        "    host, sep, port = value.partition(':')\n"
        "    return host, int(port) if sep else None\n",
        [("host only", "parse_host('lab-a.internal') == ('lab-a.internal', None)", "parse_host('lab-a.internal')"),
         ("host and port", "parse_host('lab-a.internal:8443') == ('lab-a.internal', 8443)", "parse_host('lab-a.internal:8443')"),
         ("userinfo is rejected", "parse_host('evil.com@lab-a.internal') is None", "parse_host('evil.com@lab-a.internal')"),
         ("spaces are rejected", "parse_host('lab-a.internal evil') is None", "parse_host('lab-a.internal evil')"),
         ("ipv6 literal", "parse_host('[::1]:8080') == ('::1', 8080)", "parse_host('[::1]:8080')"),
         ("bare ipv6 is rejected", "parse_host('::1') is None", "parse_host('::1')")],
        ["Reject `@` before anything else — it is the userinfo confusion trick.",
         "More than one colon means IPv6, which must be bracketed.",
         "Return the pair, not a string: the port is a separate decision downstream."],
        stretch="Never build a URL from this host value — parse it, then compare against an allow-list."),

    net_task(
        "net-ua-parse", "Pull the product out of a User-Agent",
        "Complete `client_name` so it returns the product token from a User-Agent string: the "
        "first space-separated field without its version suffix. Empty and unknown values give "
        "`'unknown'` — never guess from a partial match.\n\n"
        "**Stretch:** flag a UA with no `/` version separator as suspicious.",
        "def client_name(ua):\n    ...\n",
        "def client_name(ua):\n    ua = (ua or '').strip()\n"
        "    if not ua:\n        return 'unknown'\n"
        "    token = ua.split()[0]\n"
        "    name = token.split('/')[0]\n"
        "    return name or 'unknown'\n",
        [("curl", "client_name('curl/8.0') == 'curl'", "client_name('curl/8.0')"),
         ("chrome", "client_name('Mozilla/5.0 (X11) Chrome/120.0') == 'Mozilla'", "client_name('Mozilla/5.0 (X11) Chrome/120.0')"),
         ("empty", "client_name('') == 'unknown'", "client_name('')"),
         ("none", "client_name(None) == 'unknown'", "client_name(None)"),
         ("no version", "client_name('anvil-cli') == 'anvil-cli'", "client_name('anvil-cli')")],
        ["Take the first field, then cut at `/`.",
         "`(ua or '')` handles `None` without a separate branch.",
         "'unknown' beats an empty string — logs with empty fields are useless later."],
        stretch="A UA is self-declared and trivially spoofed; never authorise on it."),

    net_task(
        "net-wildcard", "Match a host against a wildcard pattern",
        "Certificate SANs and allow-lists use `*.example.com`. Complete `matches` so a single "
        "leading `*.` matches exactly one label: it matches `lab.example.com` but **not** "
        "`a.b.example.com` and not `example.com` itself. Anything else is an exact match.\n\n"
        "**Stretch:** make `*.example.com` also match the bare domain.",
        "def matches(host, pattern):\n    ...\n",
        "def matches(host, pattern):\n    host = (host or '').lower().rstrip('.')\n"
        "    pattern = (pattern or '').lower().rstrip('.')\n"
        "    if pattern.startswith('*.'):\n"
        "        suffix = pattern[1:]\n"
        "        if not host.endswith(suffix):\n"
        "            return False\n"
        "        rest = host[:-len(suffix)]\n"
        "        return bool(rest) and '.' not in rest\n"
        "    return host == pattern\n",
        [("one label", "matches('lab.example.com', '*.example.com') is True", "matches('lab.example.com', '*.example.com')"),
         ("two labels do not match", "matches('a.b.example.com', '*.example.com') is False", "matches('a.b.example.com', '*.example.com')"),
         ("the bare domain does not match", "matches('example.com', '*.example.com') is False", "matches('example.com', '*.example.com')"),
         ("case insensitive", "matches('LAB.example.com', '*.example.com') is True", "matches('LAB.example.com', '*.example.com')"),
         ("exact match", "matches('lab.example.com', 'lab.example.com') is True", "matches('lab.example.com', 'lab.example.com')")],
        ["A trailing dot is legal in DNS — strip it on both sides first.",
         "The leftover prefix must be exactly one label, i.e. it ends with a dot.",
         "`rest.endswith('.')` is what rejects `a.b.example.com`."],
        stretch="`*.example.com` matching `example.com` is a common policy choice — make it explicit, not accidental."),
]

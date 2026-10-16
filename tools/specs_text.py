#!/usr/bin/env python3
"""specs_text.py — tekst, kodowanie i regex (Python w Pyodide)."""
from gen_tasks import py_task

TEXT = [
    py_task("txt-rev-words", "Reverse the order of words",
            "Complete `reverse_words` so it returns the words in reverse order, whitespace "
            "collapsed. Leading and trailing whitespace disappears, and internal runs of spaces "
            "become a single one.\n\n"
            "**Stretch:** keep the punctuation attached to its word.",
            "def reverse_words(text):\n    ...\n",
            "def reverse_words(text):\n    return ' '.join(text.split()[::-1])\n",
            [("plain sentence", "reverse_words('the quick brown fox') == 'fox brown quick the'", "reverse_words('the quick brown fox')"),
             ("trims the edges", "reverse_words('  spaced out  ') == 'out spaced'", "reverse_words('  spaced out  ')"),
             ("collapses inner runs", "reverse_words('a   b\\t\\nc') == 'c b a'", "reverse_words('a   b\\t\\nc')"),
             ("empty stays empty", "reverse_words('') == ''", "reverse_words('')")],
            difficulty=2, points=90, area="Text",
            hint="`str.split()` with no argument already trims and collapses whitespace."),

    py_task("txt-title-case", "Title-case without mangling the rest",
            "Complete `title_case` so every word starts with a capital and the rest is lowercased. "
            "An empty string is returned unchanged, and `str` is left alone — a one-letter word "
            "must not become an empty string.\n\n"
            "**Stretch:** leave words that are already all-caps alone (acronyms).",
            "def title_case(text):\n    ...\n",
            "def title_case(text):\n    return ' '.join(w[:1].upper() + w[1:].lower() if w else w for w in text.split(' '))\n",
            [("two words", "title_case('hello world') == 'Hello World'", "title_case('hello world')"),
             ("already lower input", "title_case('ANVIL lab') == 'Anvil Lab'", "title_case('ANVIL lab')"),
             ("one letter", "title_case('a b') == 'A B'", "title_case('a b')"),
             ("empty", "title_case('') == ''", "title_case('')")],
            difficulty=2, points=90, area="Text",
            hint="`w[:1].upper() + w[1:].lower()` never raises on an empty string, unlike `w[0]`."),

    py_task("txt-caesar-cipher", "Shift letters and keep the case",
            "Complete `shift` so ASCII letters move by `n` places, wrapping around, and every "
            "other character stays exactly where it is. Negative shifts work. This is the toy "
            "version of a real cipher — Caesar is broken, ROT13 is obfuscation.",
            "def shift(text, n):\n    ...\n",
            "def shift(text, n):\n    out = []\n"
            "    for ch in text:\n"
            "        if 'a' <= ch <= 'z':\n"
            "            out.append(chr((ord(ch) - 97 + n) % 26 + 97))\n"
            "        elif 'A' <= ch <= 'Z':\n"
            "            out.append(chr((ord(ch) - 65 + n) % 26 + 65))\n"
            "        else:\n"
            "            out.append(ch)\n"
            "    return ''.join(out)\n",
            [("shift by one", "shift('abc', 1) == 'bcd'", "shift('abc', 1)"),
             ("wraps past z", "shift('xyz', 3) == 'abc'", "shift('xyz', 3)"),
             ("digits stay", "shift('anvil-123!', 1) == 'bowjm-123!'", "shift('anvil-123!', 1)"),
             ("negative", "shift('bcd', -1) == 'abc'", "shift('bcd', -1)"),
             ("case is preserved", "shift('Anvil', 1) == 'Bowjm'", "shift('Anvil', 1)"),
             ("empty", "shift('', 5) == ''", "shift('', 5)")],
            difficulty=2, points=110, area="Text",
            hint="Two branches, one per case: subtract 97 for lower and 65 for upper, then add 97 or 65 back."),

    py_task("txt-atbash", "Mirror the alphabet (Atbash)",
            "Complete `atbash` so `a` becomes `z`, `b` becomes `a` and so on. Case is preserved, "
            "everything else is untouched. Atbash is a fixed substitution — the same message "
            "always encrypts to the same ciphertext, which is exactly the problem.",
            "def atbash(text):\n    ...\n",
            "def atbash(text):\n    out = []\n"
            "    for ch in text:\n"
            "        if 'a' <= ch <= 'z':\n"
            "            out.append(chr(219 - ord(ch)))\n"
            "        elif 'A' <= ch <= 'Z':\n"
            "            out.append(chr(155 - ord(ch)))\n"
            "        else:\n"
            "            out.append(ch)\n"
            "    return ''.join(out)\n",
            [("lowercase", "atbash('abc') == 'zyx'", "atbash('abc')"),
             ("uppercase", "atbash('ABC') == 'ZYX'", "atbash('ABC')"),
             ("mixed", "atbash('Anvil') == 'Zmero'", "atbash('Anvil')"),
             ("digits survive", "atbash('a1z') == 'z1a'", "atbash('a1z')"),
             ("empty", "atbash('') == ''", "atbash('')")],
            difficulty=2, points=110, area="Text",
            hint="`a` is 97 and `z` is 122 — they add up to 219. Uppercase adds up to 155."),

    py_task("txt-rotation", "Rotate a list without slicing tricks",
            "Complete `rotate` so the list moves `n` places left, wrapping around. A negative `n` "
            "rotates the other way, and `n` larger than the list is fine. An empty list stays "
            "empty. `collections.deque` with `rotate` does this in one call.",
            "def rotate(items, n):\n    ...\n",
            "from collections import deque\n\ndef rotate(items, n):\n    d = deque(items)\n    d.rotate(-n)\n    return list(d)\n",
            [("simple left", "rotate([1, 2, 3, 4], 1) == [2, 3, 4, 1]", "rotate([1, 2, 3, 4], 1)"),
             ("right", "rotate([1, 2, 3, 4], -1) == [4, 1, 2, 3]", "rotate([1, 2, 3, 4], -1)"),
             ("past the end", "rotate([1, 2], 5) == [2, 1]", "rotate([1, 2], 5)"),
             ("zero is identity", "rotate([1, 2], 0) == [1, 2]", "rotate([1, 2], 0)"),
             ("empty", "rotate([], 3) == []", "rotate([], 3)")],
            difficulty=2, points=100, setup="from collections import deque\n", area="Text",
            hint="`deque.rotate` rotates **right**, so a left rotation of `n` is `rotate(-n)`. Negative values and values larger than the list need no special case."),

    py_task("txt-levenshtein", "Count the edits between two strings",
            "Complete `distance` so it returns the Levenshtein distance: the minimum number of "
            "insertions, deletions and substitutions that turn `a` into `b`. Equal strings give 0. "
            "This is what spell-checkers and `diff` count.",
            "def distance(a, b):\n    ...\n",
            "def distance(a, b):\n"
            "    prev = list(range(len(b) + 1))\n"
            "    for i, ca in enumerate(a, 1):\n"
            "        cur = [i]\n"
            "        for j, cb in enumerate(b, 1):\n"
            "            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))\n"
            "        prev = cur\n"
            "    return prev[-1]\n",
            [("identical", "distance('lab', 'lab') == 0", "distance('lab', 'lab')"),
             ("one substitution", "distance('lab', 'lac') == 1", "distance('lab', 'lac')"),
             ("one insertion", "distance('lab', 'labs') == 1", "distance('lab', 'labs')"),
             ("one deletion", "distance('labs', 'lab') == 1", "distance('labs', 'lab')"),
             ("transposition costs two", "distance('ab', 'ba') == 2", "distance('ab', 'ba')"),
             ("empty source", "distance('', 'abc') == 3", "distance('', 'abc')")],
            difficulty=4, points=260, area="Text",
            hint="One row of the matrix is enough: `prev` is the row above, `cur` the row you are building."),

    py_task("txt-longest-line", "Find the longest line and its index",
            "Complete `longest` so it returns `(index, length)` for the longest line, ignoring "
            "empty lines. Ties go to the **first** one, and an all-empty input gives `(0, 0)` "
            "rather than raising. Longest-line-first is how a debugger frames a stack trace.",
            "def longest(lines):\n    ...\n",
            "def longest(lines):\n"
            "    best_i, best_n = 0, 0\n"
            "    for i, line in enumerate(lines):\n"
            "        if line and len(line) > best_n:\n"
            "            best_i, best_n = i, len(line)\n"
            "    return best_i, best_n\n",
            [("single line", "longest(['ab', 'abcd', 'abc']) == (1, 4)", "longest(['ab', 'abcd', 'abc'])"),
             ("first wins a tie", "longest(['abc', 'xyz']) == (0, 3)", "longest(['abc', 'xyz'])"),
             ("empty lines are skipped", "longest(['', 'ab', '']) == (1, 2)", "longest(['', 'ab', ''])"),
             ("all empty", "longest(['', '']) == (0, 0)", "longest(['', ''])"),
             ("no lines", "longest([]) == (0, 0)", "longest([])")],
            difficulty=2, points=100, area="Text",
            hint="Use `>` and not `>=` — that is what makes the first of two equal lines win."),

    py_task("txt-find-all", "Find every match without the loop-around-missed-one bug",
            "Complete `find_all` so it returns the start index of **every** match of `needle` in "
            "`haystack`, including overlapping ones. An empty needle returns an empty list. The "
            "classic bug here is advancing by one instead of by the length of the match.",
            "def find_all(haystack, needle):\n    ...\n",
            "def find_all(haystack, needle):\n"
            "    out = []\n"
            "    if not needle:\n"
            "        return out\n"
            "    start = 0\n"
            "    while True:\n"
            "        i = haystack.find(needle, start)\n"
            "        if i == -1:\n"
            "            return out\n"
            "        out.append(i)\n"
            "        start = i + 1\n",
            [("single match", "find_all('abcd', 'bc') == [1]", "find_all('abcd', 'bc')"),
             ("repeated", "find_all('aaaa', 'a') == [0, 1, 2, 3]", "find_all('aaaa', 'a')"),
             ("two matches", "find_all('xaxbxc', 'x') == [0, 2, 4]", "find_all('xaxbxc', 'x')"),
             ("overlapping", "find_all('aaa', 'aa') == [0, 1]", "find_all('aaa', 'aa')"),
             ("nothing", "find_all('abc', 'z') == []", "find_all('abc', 'z')"),
             ("empty needle", "find_all('abc', '') == []", "find_all('abc', '')")],
            difficulty=3, points=150, area="Text",
            hint="`str.find(sub, start)` returns `-1` when there is nothing left — that is your loop condition. Move the start forward by **one**, not by the length of the needle, or overlapping matches are lost."),

    py_task("txt-template", "Fill a template without str.format pitfalls",
            "Complete `fill` so `{name}` becomes the value from `values`. An unknown key and a "
            "missing key both become an empty string rather than raising. This is what a log "
            "formatter does with a record it does not fully understand.",
            "def fill(template, values):\n    ...\n",
            "def fill(template, values):\n"
            "    out = []\n"
            "    i = 0\n"
            "    while i < len(template):\n"
            "        if template.startswith('{', i):\n"
            "            j = template.find('}', i)\n"
            "            if j != -1:\n"
            "                out.append(str(values.get(template[i + 1:j], '')))\n"
            "                i = j + 1\n"
            "                continue\n"
            "        out.append(template[i])\n"
            "        i += 1\n"
            "    return ''.join(out)\n",
            [("one key", "fill('hi {name}', {'name': 'kija'}) == 'hi kija'", "fill('hi {name}', {'name': 'kija'})"),
             ("two keys", "fill('{a}-{b}', {'a': 1, 'b': 2}) == '1-2'", "fill('{a}-{b}', {'a': 1, 'b': 2})"),
             ("unknown key", "fill('{a}{b}', {'a': 1}) == '1'", "fill('{a}{b}', {'a': 1})"),
             ("no keys", "fill('plain', {}) == 'plain'", "fill('plain', {})"),
             ("empty", "fill('', {'a': 1}) == ''", "fill('', {'a': 1})")],
            difficulty=3, points=170, area="Text",
            hint="Walk the string with an index and use `str.find('}', i)` to find where a placeholder ends."),

    py_task("txt-truncate", "Truncate without breaking a word",
            "Complete `truncate` so the result is at most `width` characters, ending in `…` when it "
            "had to cut. Never cut in the middle of a word: if the last full word does not fit, "
            "everything after the previous space goes too. `width` below 1 returns an empty string.",
            "def truncate(text, width):\n    ...\n",
            "def truncate(text, width):\n"
            "    if width < 1:\n"
            "        return ''\n"
            "    if len(text) <= width:\n"
            "        return text\n"
            "    cut = text[:width - 1]\n"
            "    if ' ' in cut:\n"
            "        cut = cut[:cut.rindex(' ')]\n"
            "    return cut.rstrip() + '…'\n",
            [("short enough", "truncate('hello', 10) == 'hello'", "truncate('hello', 10)"),
             ("exact fit", "truncate('hello', 5) == 'hello'", "truncate('hello', 5)"),
             ("cuts at a word", "truncate('hello brave world', 12) == 'hello…'", "truncate('hello brave world', 12)"),
             ("one long word", "truncate('supercalifragilistic', 8) == 'superca…'", "truncate('supercalifragilistic', 8)"),
             ("width zero", "truncate('hello', 0) == ''", "truncate('hello', 0)"),
             ("negative width", "truncate('hello', -3) == ''", "truncate('hello', -3)")],
            difficulty=3, points=150, area="Text",
            hint="Take `width - 1` characters to leave room for the ellipsis, then cut back to the last space."),

    py_task("txt-csv-row", "Parse one CSV row with quotes and commas",
            "Complete `parse_row` so it splits a single CSV line into fields. A field wrapped in "
            "double quotes may contain commas, and `""` inside a quoted field is one literal "
            "quote. Unterminated quotes return `None` — a real parser refuses, it does not guess.",
            "def parse_row(line):\n    ...\n",
            "def parse_row(line):\n"
            "    out, field, i, quoted = [], '', 0, False\n"
            "    while i < len(line):\n"
            "        ch = line[i]\n"
            "        if quoted:\n"
            "            if ch == '\"':\n"
            "                if i + 1 < len(line) and line[i + 1] == '\"':\n"
            "                    field += '\"'\n"
            "                    i += 1\n"
            "                else:\n"
            "                    quoted = False\n"
            "            else:\n"
            "                field += ch\n"
            "        elif ch == '\"':\n"
            "            quoted = True\n"
            "        elif ch == ',':\n"
            "            out.append(field)\n"
            "            field = ''\n"
            "        else:\n"
            "            field += ch\n"
            "        i += 1\n"
            "    if quoted:\n"
            "        return None\n"
            "    out.append(field)\n"
            "    return out\n",
            [("plain", "parse_row('a,b,c') == ['a', 'b', 'c']", "parse_row('a,b,c')"),
             ("quoted comma", "parse_row('a,\"b,1\",c') == ['a', 'b,1', 'c']", "parse_row('a,\"b,1\",c')"),
             ("escaped quote", "parse_row('a,\"b\"\"c\"') == ['a', 'b\"c']", "parse_row('a,\"b\"\"c\"')"),
             ("empty fields", "parse_row('a,,c') == ['a', '', 'c']", "parse_row('a,,c')"),
             ("single field", "parse_row('a') == ['a']", "parse_row('a')"),
             ("unterminated", "parse_row('a,\"b') is None", "parse_row('a,\"b')")],
            difficulty=4, points=280, setup="", area="Text",
            hint="A `quoted` flag plus an index is enough — no regex, no library."),
]

TEXT_CODEC = [
    py_task("txt-base64url", "Decode base64url padding correctly",
            "base64url uses `-` and `_` and drops the `=` padding. Complete `b64d` so it puts the "
            "padding back before decoding and returns bytes. A token from a header arrives like "
            "this — and `base64.b64decode` raises on the wrong alphabet.",
            "def b64d(text):\n    ...\n",
            "import base64\n\ndef b64d(text):\n    pad = '=' * (-len(text) % 4)\n    return base64.urlsafe_b64decode(text + pad)\n",
            [("no padding needed", "b64d('YWJj') == b'abc'", "b64d('YWJj')"),
             ("one pad char", "b64d('YQ') == b'a'", "b64d('YQ')"),
             ("two pad chars", "b64d('YWI') == b'ab'", "b64d('YWI')"),
             ("url alphabet", "b64d('_w') == b'\\xff'", "b64d('_w')"),
             ("empty", "b64d('') == b''", "b64d('')")],
            difficulty=3, points=160, setup="import base64\n", area="Encoding",
            hint="`'-' * (-len(s) % 4)` adds 0–3 characters — the length mod 4 is the count."),

    py_task("txt-hexdump-decode", "Read a hexdump back into bytes",
            "Complete `parse_hexdump` so it returns the raw bytes of an `xxd`-style dump, ignoring "
            "the offset column, the hex pairs and the ASCII gutter. Lines with no hex digits are "
            "skipped. A hexdump is what you get when a binary payload has to travel through a log.",
            "def parse_hexdump(dump):\n    ...\n",
            "def parse_hexdump(dump):\n"
            "    out = bytearray()\n"
            "    for line in dump.splitlines():\n"
            "        parts = line.split(':')\n"
            "        if len(parts) < 2:\n"
            "            continue\n"
            "        for tok in parts[1].split():\n"
            "            if len(tok) == 2 and all(c in '0123456789abcdefABCDEF' for c in tok):\n"
            "                out.append(int(tok, 16))\n"
            "    return bytes(out)\n",
            [("one line", "parse_hexdump('0000: 61 62  hi') == b'ab'", "parse_hexdump('0000: 61 62  hi')"),
             ("two lines", "parse_hexdump('0: 61\\n10: 62') == b'ab'", "parse_hexdump('0: 61\\n10: 62')"),
             ("no colon", "parse_hexdump('garbage') == b''", "parse_hexdump('garbage')"),
             ("empty", "parse_hexdump('') == b''", "parse_hexdump('')")],
            difficulty=2, points=120, area="Encoding",
            hint="`int(tok, 16)` parses two hex digits; the ASCII gutter fails `all(...)` so it is skipped."),

    py_task("txt-rot13", "Apply ROT13 twice and get the original back",
            "Complete `rot13` so letters shift by 13 and everything else is untouched. Applying it "
            "twice returns the input — which is exactly why it is encoding and not encryption.",
            "import codecs\n\ndef rot13(text):\n    ...\n",
            "import codecs\n\ndef rot13(text):\n    return codecs.encode(text, 'rot_13')\n",
            [("letter", "rot13('a') == 'n'", "rot13('a')"),
             ("sentence", "rot13('lab') == 'yno'", "rot13('lab')"),
             ("case kept", "rot13('Anvil') == 'Naivy'", "rot13('Anvil')"),
             ("twice is identity", "rot13(rot13('anvil lab')) == 'anvil lab'", "rot13(rot13('anvil lab'))"),
             ("digits survive", "rot13('a1') == 'n1'", "rot13('a1')")],
            difficulty=2, points=80, setup="import codecs\n", area="Encoding",
            hint="`codecs.encode(text, 'rot_13')` does the whole thing in C."),

    py_task("txt-crc32", "Compute a CRC32 the way zlib does",
            "A CRC32 is not a hash you design — it is a fixed 32-bit error-detecting code that "
            "every zip and PNG already uses. Complete `crc32` so it returns the same number as "
            "`zlib.crc32`, as a non-negative integer. `zlib.crc32` is signed, which is the trap.",
            "def crc32(data):\n    ...\n",
            "import zlib\n\ndef crc32(data):\n    return zlib.crc32(data) & 0xffffffff\n",
            [("empty", "crc32(b'') == 0", "crc32(b'')"),
             ("abc", "crc32(b'abc') == 891568578", "crc32(b'abc')"),
             ("never negative", "crc32(b'\\xff' * 64) > 0", "crc32(b'\\xff' * 64)"),
             ("one bit changes it", "crc32(b'ab') != crc32(b'ac')", "a changed bit changes the checksum")],
            difficulty=2, points=120, setup="import zlib\n", area="Encoding",
            hint="`zlib.crc32` returns a signed 32-bit int; mask it with `& 0xffffffff`."),

    py_task("txt-runlength", "Run-length encode and decode",
            "Complete `rle_encode` so runs of the same character collapse into `count` + `char`, "
            "and `rle_decode` reverses it. A count of 1 is still written out, so the format "
            "round-trips. This is how a sparse image, a fax or a very repetitive log line shrinks.",
            "def rle_encode(text):\n    ...\n\ndef rle_decode(text):\n    ...\n",
            "def rle_encode(text):\n"
            "    out = []\n"
            "    if not text:\n"
            "        return ''\n"
            "    prev, n = text[0], 1\n"
            "    for ch in text[1:]:\n"
            "        if ch == prev:\n"
            "            n += 1\n"
            "        else:\n"
            "            out.append(str(n) + prev)\n"
            "            prev, n = ch, 1\n"
            "    out.append(str(n) + prev)\n"
            "    return ''.join(out)\n\n"
            "def rle_decode(text):\n"
            "    out, i = [], 0\n"
            "    while i < len(text):\n"
            "        j = i\n"
            "        while j < len(text) and text[j].isdigit():\n"
            "            j += 1\n"
            "        if j == i or j >= len(text):\n"
            "            return None\n"
            "        out.append(text[j] * int(text[i:j]))\n"
            "        i = j + 1\n"
            "    return ''.join(out)\n",
            [("encode a run", "rle_encode('aaab') == '3a1b'", "rle_encode('aaab')"),
             ("single of one", "rle_encode('ab') == '1a1b'", "rle_encode('ab')"),
             ("encode empty", "rle_encode('') == ''", "rle_encode('')"),
             ("decode", "rle_decode('3a1b') == 'aaab'", "rle_decode('3a1b')"),
             ("round trip", "rle_decode(rle_encode('aaabbc')) == 'aaabbc'", "rle_decode(rle_encode('aaabbc'))"),
             ("broken input", "rle_decode('a3') is None", "rle_decode('a3')")],
            difficulty=3, points=170, area="Encoding",
            hint="Encode by remembering the previous character and its count; decode by consuming digits, then one character."),

    py_task("txt-csv-escape", "Quote a CSV field only when it needs it",
            "Complete `csv_field` so it quotes a value only when it contains a comma, a quote or a "
            "newline, and doubles any quote inside. An empty value is not quoted. This is the rule "
            "in RFC 4180, and getting it wrong silently shifts every column to the right.",
            "def csv_field(value):\n    ...\n",
            "def csv_field(value):\n"
            "    s = str(value)\n"
            "    if any(c in s for c in ',\"\\n') or '\\r' in s:\n"
            "        return '\"' + s.replace('\"', '\"\"') + '\"'\n"
            "    return s\n",
            [("plain", "csv_field('lab') == 'lab'", "csv_field('lab')"),
             ("comma", "csv_field('a,b') == '\"a,b\"'", "csv_field('a,b')"),
             ("quote doubles", "csv_field('say \"hi\"') == '\"say \"\"hi\"\"\"'", "csv_field('say \"hi\"')"),
             ("newline", "csv_field('a\\nb') == '\"a\\nb\"'", "csv_field('a\\nb')"),
             ("empty is bare", "csv_field('') == ''", "csv_field('')")],
            difficulty=2, points=110, area="Encoding",
            hint="Test the three characters, then wrap and double the quotes — no condition can be forgotten."),

    py_task("txt-urlencode", "Percent-encode a query value",
            "Complete `q` so it percent-encodes everything outside `A-Za-z0-9-._~`, leaving those "
            "alone and turning a space into `+`. Uppercase hex digits only. A space written as `%20` "
            "inside a query string is legal but `+` is what every form sends.",
            "def q(value):\n    ...\n",
            "def q(value):\n"
            "    out = []\n"
            "    for ch in str(value):\n"
            "        if ch.isalnum() and ch.isascii() or ch in '-._~':\n"
            "            out.append(ch)\n"
            "        elif ch == ' ':\n"
            "            out.append('+')\n"
            "        else:\n"
            "            out.extend('%%%02X' % b for b in ch.encode('utf-8'))\n"
            "    return ''.join(out)\n",
            [("plain", "q('lab') == 'lab'", "q('lab')"),
             ("space", "q('a b') == 'a+b'", "q('a b')"),
             ("reserved", "q('a&b=c') == 'a%26b%3Dc'", "q('a&b=c')"),
             ("slash", "q('/admin') == '%2Fadmin'", "q('/admin')"),
             ("unreserved kept", "q('a-b._~') == 'a-b._~'", "q('a-b._~')"),
             ("unicode is utf-8", "q('ł') == '%C5%82'", "q('ł')")],
            difficulty=3, points=160, area="Encoding",
            hint="Encode the character to UTF-8 bytes first, then format each byte as `%%%02X`."),

    py_task("txt-json-depth", "Measure the nesting depth of a JSON document",
            "Complete `depth` so it returns how deep the structure nests — a flat dict is 1, a "
            "dict holding a list holding a dict is 3. Counts **strings** inside, so brackets "
            "inside text do not count. A recursive-descent parser is exactly this walk.",
            "import json\n\ndef depth(raw):\n    ...\n",
            "import json\n\ndef depth(raw):\n"
            "    def walk(node, level):\n"
            "        if isinstance(node, dict):\n"
            "            return max([level + 1] + [walk(v, level + 1) for v in node.values()])\n"
            "        if isinstance(node, list):\n"
            "            return max([level + 1] + [walk(v, level + 1) for v in node])\n"
            "        return level\n"
            "    try:\n"
            "        return walk(json.loads(raw), 0)\n"
            "    except Exception:\n"
            "        return None\n",
            [("flat object", "depth('{\"a\": 1}') == 1", "depth('{\"a\": 1}')"),
             ("two levels", "depth('{\"a\": {\"b\": 1}}') == 2", "depth('{\"a\": {\"b\": 1}}')"),
             ("list counts", "depth('[1, 2, 3]') == 1", "depth('[1, 2, 3]')"),
             ("three levels", "depth('{\"a\": [{\"b\": 1}]}') == 3", "depth('{\"a\": [{\"b\": 1}]}')"),
             ("brackets in strings", "depth('{\"a\": \"[[[\"}') == 1", "depth('{\"a\": \"[[[\"}')"),
             ("broken json", "depth('{oops') is None", "depth('{oops')")],
            difficulty=3, points=190, setup="import json\n", area="Encoding",
            hint="One recursive helper that returns `max` over the children's depth, starting at the current level."),
]

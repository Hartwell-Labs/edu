#!/usr/bin/env python3
"""specs_data.py — struktury danych, JSON, regex, agregacje (Python w Pyodide)."""
from gen_tasks import py_task

DATA = [
    py_task("dat-flatten", "Flatten a nested dict, keeping the path",
            "Complete `flatten` so `{'a': {'b': 1}}` becomes `{'a.b': 1}`. Keys are joined with a "
            "dot and lists keep their index as part of the path, so nothing collides. This is what "
            "turns a structured log record into something a search index can hold.",
            "def flatten(node, prefix=''):\n    ...\n",
            "def flatten(node, prefix=''):\n"
            "    out = {}\n"
            "    if isinstance(node, dict):\n"
            "        for k, v in node.items():\n"
            "            out.update(flatten(v, f'{prefix}.{k}' if prefix else str(k)))\n"
            "    elif isinstance(node, list):\n"
            "        for i, v in enumerate(node):\n"
            "            out.update(flatten(v, f'{prefix}.{i}'))\n"
            "    else:\n"
            "        out[prefix] = node\n"
            "    return out\n",
            [("one level", "flatten({'a': 1}) == {'a': 1}", "flatten({'a': 1})"),
             ("two levels", "flatten({'a': {'b': 1}}) == {'a.b': 1}", "flatten({'a': {'b': 1}})"),
             ("list index", "flatten({'a': [7]}) == {'a.0': 7}", "flatten({'a': [7]})"),
             ("mixed", "flatten({'a': [{'b': 2}]}) == {'a.0.b': 2}", "flatten({'a': [{'b': 2}]})"),
             ("empty dict", "flatten({}) == {}", "flatten({})")],
            difficulty=3, points=180, area="Data",
            hint="One recursive function, and a `prefix` argument that grows as you descend."),

    py_task("dat-unique-stable", "Deduplicate without breaking the order",
            "Complete `unique` so it returns the items with duplicates removed, **first "
            "occurrence wins**, and the original order kept. A `set` alone gets you the values "
            "but throws the order away — the trap in almost every interview about this.",
            "def unique(items):\n    ...\n",
            "def unique(items):\n"
            "    seen, out = set(), []\n"
            "    for x in items:\n"
            "        if x not in seen:\n"
            "            seen.add(x)\n"
            "            out.append(x)\n"
            "    return out\n",
            [("already unique", "unique([1, 2, 3]) == [1, 2, 3]", "unique([1, 2, 3])"),
             ("middle duplicate", "unique([1, 2, 1]) == [1, 2]", "unique([1, 2, 1])"),
             ("order survives", "unique(['b', 'a', 'b']) == ['b', 'a']", "unique(['b', 'a', 'b'])"),
             ("strings", "unique('aaba') == ['a', 'b']", "unique('aaba')"),
             ("empty", "unique([]) == []", "unique([])")],
            difficulty=2, points=110, area="Data",
            hint="A `set` for the membership test and a separate list for the output — the order lives in the list."),

    py_task("dat-groupby", "Group rows by a key, sorted by key",
            "Complete `group_by` so it returns a dict mapping each key to the list of rows that "
            "carry it, and the keys come back in sorted order. Rows missing the key field are "
            "skipped rather than filed under `None`. This is the shape every `awk '{print $1}'` "
            "pipeline produces.",
            "def group_by(rows, key):\n    ...\n",
            "def group_by(rows, key):\n"
            "    out = {}\n"
            "    for row in rows:\n"
            "        if key not in row:\n"
            "            continue\n"
            "        out.setdefault(row[key], []).append(row)\n"
            "    return {k: out[k] for k in sorted(out)}\n",
            [("one group", "group_by([{'a': 1}], 'a') == {1: [{'a': 1}]}", "group_by([{'a': 1}], 'a')"),
             ("two groups", "list(group_by([{'a': 2}, {'a': 1}], 'a')) == [1, 2]", "group_by([{'a': 2}, {'a': 1}], 'a')"),
             ("missing key skipped", "group_by([{'b': 1}], 'a') == {}", "group_by([{'b': 1}], 'a')"),
             ("no rows", "group_by([], 'a') == {}", "group_by([], 'a')")],
            difficulty=2, points=130, area="Data",
            hint="`setdefault(key, []).append(row)` does the grouping; sort the keys at the end."),

    py_task("dat-merge-defaults", "Merge settings so explicit wins",
            "Complete `merge` so the result has every key from both dicts; a key in `overrides` "
            "wins, otherwise the default stays. Keys that are `None` in the overrides fall back to "
            "the default — an unset value should not erase a configured one.",
            "def merge(defaults, overrides):\n    ...\n",
            "def merge(defaults, overrides):\n"
            "    out = dict(defaults)\n"
            "    for k, v in (overrides or {}).items():\n"
            "        if v is not None:\n"
            "            out[k] = v\n"
            "    return out\n",
            [("plain override", "merge({'a': 1}, {'a': 2}) == {'a': 2}", "merge({'a': 1}, {'a': 2})"),
             ("default kept", "merge({'a': 1}, {}) == {'a': 1}", "merge({'a': 1}, {})"),
             ("new key added", "merge({'a': 1}, {'b': 2}) == {'a': 1, 'b': 2}", "merge({'a': 1}, {'b': 2})"),
             ("none falls back", "merge({'a': 1}, {'a': None}) == {'a': 1}", "merge({'a': 1}, {'a': None})"),
             ("overrides is None", "merge({'a': 1}, None) == {'a': 1}", "merge({'a': 1}, None)")],
            difficulty=2, points=100, area="Data",
            hint="Copy the defaults first, then loop the overrides and skip `None` values."),

    py_task("dat-lru-cache", "Build an LRU cache with an ordered dict",
            "Complete `Cache.get` so it returns the value and **moves the key to the end**, and "
            "`Cache.put` so it stores and evicts the oldest key once the size limit is reached. "
            "`OrderedDict.move_to_end` and `popitem(last=False)` are the whole trick — this is how "
            "memcached and every in-process cache in Python works.",
            "from collections import OrderedDict\n\nclass Cache:\n    def __init__(self, size):\n        self.size = size\n        self.d = OrderedDict()\n\n    def get(self, key):\n        ...\n\n    def put(self, key, value):\n        ...\n",
            "from collections import OrderedDict\n\nclass Cache:\n"
            "    def __init__(self, size):\n"
            "        self.size = size\n"
            "        self.d = OrderedDict()\n\n"
            "    def get(self, key):\n"
            "        if key not in self.d:\n"
            "            return None\n"
            "        self.d.move_to_end(key)\n"
            "        return self.d[key]\n\n"
            "    def put(self, key, value):\n"
            "        if key in self.d:\n"
            "            self.d.move_to_end(key)\n"
            "        self.d[key] = value\n"
            "        while len(self.d) > self.size:\n"
            "            self.d.popitem(last=False)\n",
            [("hit returns the value", "(lambda c: (c.put('a', 1), c.get('a'))[1])(Cache(2)) == 1", "put then get"),
             ("miss is None", "Cache(2).get('nope') is None", "get on an empty cache"),
             ("oldest is evicted", "(lambda c: (c.put('a', 1), c.put('b', 2), c.put('c', 3), c.get('a'))[3])(Cache(2)) is None", "three puts into a two-slot cache"),
             ("a read refreshes the entry", "(lambda c: (c.put('a', 1), c.put('b', 2), c.get('a'), c.put('c', 3), c.get('a'))[4])(Cache(2)) == 1", "get between two puts"),
             ("the newest survives", "(lambda c: (c.put('a', 1), c.put('b', 2), c.get('b'))[2])(Cache(2)) == 2", "get the newest key")],
            difficulty=4, points=300, setup="from collections import OrderedDict\n", area="Data",
            hint="`move_to_end(key)` refreshes, and `popitem(last=False)` removes the front — that is the whole LRU."),

    py_task("dat-two-sum", "Find the pair that adds up, in one pass",
            "Complete `two_sum` so it returns the **indices** of the two values that add to the "
            "target, smallest first, or `None` when there is no pair. A dict of already-seen values "
            "gets it in one pass instead of the nested loop.",
            "def two_sum(nums, target):\n    ...\n",
            "def two_sum(nums, target):\n"
            "    seen = {}\n"
            "    for i, n in enumerate(nums):\n"
            "        if target - n in seen:\n"
            "            return [seen[target - n], i]\n"
            "        seen[n] = i\n"
            "    return None\n",
            [("simple pair", "two_sum([2, 7, 11], 9) == [0, 1]", "two_sum([2, 7, 11], 9)"),
             ("later pair", "two_sum([3, 2, 4], 6) == [1, 2]", "two_sum([3, 2, 4], 6)"),
             ("same value twice", "two_sum([3, 3], 6) == [0, 1]", "two_sum([3, 3], 6)"),
             ("no pair", "two_sum([1, 2], 100) is None", "two_sum([1, 2], 100)"),
             ("empty", "two_sum([], 0) is None", "two_sum([], 0)")],
            difficulty=2, points=140, area="Data",
            hint="Keep a dict of value → index; for each number ask whether `target - n` is already in it."),

    py_task("dat-balanced-brackets", "Tell whether brackets balance",
            "Complete `balanced` so it returns `True` when every `()[]{}` opened is closed in the "
            "right order. Text outside brackets is ignored, and an unclosed bracket at the end is "
            "`False`. A stack beats any count-based approach — order matters.",
            "def balanced(text):\n    ...\n",
            "def balanced(text):\n"
            "    pairs = {')': '(', ']': '[', '}': '{'}\n"
            "    stack = []\n"
            "    for ch in text:\n"
            "        if ch in '([{':\n"
            "            stack.append(ch)\n"
            "        elif ch in pairs:\n"
            "            if not stack or stack.pop() != pairs[ch]:\n"
            "                return False\n"
            "    return not stack\n",
            [("simple", "balanced('()') is True", "balanced('()')"),
             ("nested", "balanced('([]{})') is True", "balanced('([]{})')"),
             ("wrong order", "balanced('(]') is False", "balanced('(]')"),
             ("unclosed", "balanced('(') is False", "balanced('(')"),
             ("text around it", "balanced('a) b') is False", "balanced('a) b')"),
             ("nothing at all", "balanced('abc') is True", "balanced('abc')")],
            difficulty=2, points=130, area="Data",
            hint="Push openers; on a closer compare with `stack[-1]` or `pop()` and bail on a mismatch."),

    py_task("dat-matrix-mult", "Multiply two matrices",
            "Complete `matmul` so it returns the product of two matrices given as lists of rows. "
            "Mismatched inner dimensions raise `ValueError` rather than returning nonsense — a "
            "silent wrong answer here is how a numerical pipeline goes wrong for a year.",
            "def matmul(a, b):\n    ...\n",
            "def matmul(a, b):\n"
            "    if not a or not b or len(a[0]) != len(b):\n"
            "        raise ValueError('shape mismatch')\n"
            "    return [[sum(a[i][k] * b[k][j] for k in range(len(b)))\n"
            "             for j in range(len(b[0]))]\n"
            "            for i in range(len(a))]\n",
            [("1x1", "matmul([[2]], [[3]]) == [[6]]", "matmul([[2]], [[3]])"),
             ("2x2", "matmul([[1, 2], [3, 4]], [[5, 6], [7, 8]]) == [[19, 22], [43, 50]]", "2x2 product"),
             ("identity", "matmul([[1, 0], [0, 1]], [[7, 8], [9, 10]]) == [[7, 8], [9, 10]]", "identity"),
             ("1x3 times 3x1", "matmul([[1, 2, 3]], [[4], [5], [6]]) == [[32]]", "a dot product as a matrix")],
            difficulty=3, points=180, area="Data",
            hint="A triple comprehension: `i` over rows of `a`, `j` over columns of `b`, `k` over the shared dimension."),
]

DATA_RE = [
    py_task("dat-regex-extract", "Extract every IP address from a line",
            "Complete `ips` so it returns every IPv4 address in the text as a string, in order of "
            "appearance, without duplicates. An octet is 0–255, so `999.1.1.1` is not an address. "
            "`re.findall` with a numeric range in the pattern is the whole lesson.",
            "import re\n\ndef ips(text):\n    ...\n",
            "import re\n\ndef ips(text):\n"
            "    return list(dict.fromkeys(re.findall(r'\\b(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}\\b', text)))\n",
            [("one address", "ips('from 10.0.0.7 ok') == ['10.0.0.7']", "ips('from 10.0.0.7 ok')"),
             ("two", "ips('10.0.0.7 and 8.8.8.8') == ['10.0.0.7', '8.8.8.8']", "ips('10.0.0.7 and 8.8.8.8')"),
             ("deduplicated", "ips('1.1.1.1 1.1.1.1') == ['1.1.1.1']", "ips('1.1.1.1 1.1.1.1')"),
             ("out of range rejected", "ips('999.1.1.1') == []", "ips('999.1.1.1')"),
             ("nothing", "ips('no addresses here') == []", "ips('no addresses here')")],
            difficulty=3, points=200, setup="import re\n", area="Regex",
            hint="`(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)` matches one valid octet; repeat it three more times with `\\.`."),

    py_task("dat-regex-anchors", "Validate a version string with anchors",
            "Complete `valid_version` so it accepts exactly `MAJOR.MINOR.PATCH` with numeric parts, "
            "nothing before or after. `re.fullmatch` is the tool: `match` alone would accept "
            "`1.2.3-rc1`. A version check that is too loose is a real supply-chain bug.",
            "import re\n\ndef valid_version(text):\n    ...\n",
            "import re\n\ndef valid_version(text):\n"
            "    return re.fullmatch(r'[0-9]+\\.[0-9]+\\.[0-9]+', text or '') is not None\n",
            [("plain", "valid_version('1.2.3') is True", "valid_version('1.2.3')"),
             ("two digits", "valid_version('10.20.30') is True", "valid_version('10.20.30')"),
             ("suffix rejected", "valid_version('1.2.3-rc1') is False", "valid_version('1.2.3-rc1')"),
             ("missing patch", "valid_version('1.2') is False", "valid_version('1.2')"),
             ("leading text", "valid_version('v1.2.3') is False", "valid_version('v1.2.3')"),
             ("empty", "valid_version('') is False", "valid_version('')")],
            difficulty=2, points=110, setup="import re\n", area="Regex",
            hint="`re.fullmatch` anchors both ends for you; without it, `match` is only half an anchor."),

    py_task("dat-regex-greedy", "Fix a greedy quantifier",
            "Complete `first_token` so it returns only the **first** tag from `<a><b></a></b>`, not "
            "the greedy `<.*>`. This is the bug behind a hundred regex denial-of-service findings: "
            "`.*` backtracks catastrophically on a long line.",
            "import re\n\ndef first_token(text):\n    ...\n",
            "import re\n\ndef first_token(text):\n"
            "    m = re.search(r'<[^>]*>', text or '')\n"
            "    return m.group(0) if m else None\n",
            [("first tag", "first_token('<a><b>') == '<a>'", "first_token('<a><b>')"),
             ("nested", "first_token('<a><b></a></b>') == '<a>'", "first_token('<a><b></a></b>')"),
             ("attributes kept", "first_token('<a href=\"x\">y') == '<a href=\"x\">'", "first_token('<a href=\"x\">y')"),
             ("no tag", "first_token('plain') is None", "first_token('plain')"),
             ("empty", "first_token('') is None", "first_token('')")],
            difficulty=3, points=150, setup="import re\n", area="Regex",
            hint="`<[^>]*>` cannot cross a closing angle bracket, so it cannot be greedy."),

    py_task("dat-rekey", "Use a replacement function in re.sub",
            "Complete `mask_digits` so every digit in a string becomes `#` — except in a word "
            "that starts with `id`, which is an identifier and stays readable. `re.sub` takes a "
            "**function** as the replacement, which is how you redact without a second regex; a "
            "lookbehind of fixed length will not do, because the prefix has no fixed width.",
            "import re\n\ndef mask_digits(text):\n    ...\n",
            "import re\n\ndef mask_digits(text):\n"
            "    def repl(m):\n"
           "        tok = m.group(0)\n"
           "        return tok if tok.lower().startswith('id') else re.sub(r'\\d', '#', tok)\n"
           "    return re.sub(r'\\w+', repl, text or '')\n",
            [("plain digits", "mask_digits('a1b22') == 'a#b##'", "mask_digits('a1b22')"),
             ("id kept", "mask_digits('id42') == 'id42'", "mask_digits('id42')"),
             ("longer id word kept", "mask_digits('idx7') == 'idx7'", "mask_digits('idx7')"),
             ("id at the start", "mask_digits('id7 x8') == 'id7 x#'", "mask_digits('id7 x8')"),
             ("no digits", "mask_digits('abc') == 'abc'", "mask_digits('abc')"),
             ("empty", "mask_digits('') == ''", "mask_digits('')")],
            difficulty=4, points=270, setup="import re\n", area="Regex",
            hint="Match whole words with `\\w+` and decide inside the replacement function — that is where you can look at the whole token."),

    py_task("dat-split-keep", "Split but keep the delimiter",
            "Complete `split_keep` so `'a,b,c'` becomes `['a', ',', 'b', ',', 'c']` — the delimiters "
            "stay in the list. `re.split` with a **capturing group** does this; without the "
            "parentheses the separators are consumed.",
            "import re\n\ndef split_keep(text):\n    ...\n",
            "import re\n\ndef split_keep(text):\n"
            "    return re.split(r'(,)', text or '')\n",
            [("one comma", "split_keep('a,b') == ['a', ',', 'b']", "split_keep('a,b')"),
             ("two commas", "split_keep('a,b,c') == ['a', ',', 'b', ',', 'c']", "split_keep('a,b,c')"),
             ("no comma", "split_keep('abc') == ['abc']", "split_keep('abc')"),
             ("empty", "split_keep('') == ['']", "split_keep('')")],
            difficulty=2, points=120, setup="import re\n", area="Regex",
            hint="The parentheses around `,` are what make `re.split` return the separators too."),
]

#!/usr/bin/env python3
"""specs_safe.py — bezpieczne API, statystyki, quizy i zadania maszyny labowej."""
from gen_tasks import crypto_task, net_task, quiz, vm_task, task, tests

# ============================================================ bezpieczne API
SAFE = [
    crypto_task(
        "safe-shell-quote", "Quote an argument for a shell",
        "Complete `shell_arg` so a value can never break out of its argument: wrap it in single "
        "quotes and replace each internal `'` with `'\\''`. Then `shell_arg(\"a'b\")` must survive "
        "a real shell round trip.\n\n"
        "**Stretch:** return the whole command line, and show why double quotes are not enough.",
        "import shlex\n\ndef shell_arg(value):\n    ...\n",
        "def shell_arg(value):\n    return \"'\" + str(value).replace(\"'\", \"'\\\\''\") + \"'\"\n",
        [("plain value", "shell_arg('lab') == \"'lab'\"", "shell_arg('lab')"),
         ("no bare quotes survive", "'\\'' in shell_arg(\"a'b\")", "shell_arg(\"a'b\")"),
         ("spaces are safe", "shell_arg('two words') == \"'two words'\"", "shell_arg('two words')"),
         ("a command injection is inert", "shlex.split(shell_arg('x; rm -rf /')) == ['x; rm -rf /']", "shell_arg('x; rm -rf /')"),
         ("shlex agrees", "shlex.split(shell_arg('a b')) == ['a b']", "shlex.split(shell_arg('a b'))"),
         ("newline cannot split the command", "shlex.split(shell_arg('a\\nb')) == ['a\\nb']", "shlex.split(shell_arg('a\\nb'))")],
        ["Single quotes suppress every shell expansion — that is the whole trick.",
         "An embedded `'` is closed, escaped and reopened: `'\\''`.",
         "`shlex.split` in the tests proves the result parses back to one argument."],
        setup="import shlex\n",
        stretch="Better still: skip the shell entirely and pass an argument list."),

    crypto_task(
        "safe-path-join", "Join paths without escaping the root",
        "Complete `safe_join(root, *parts)` so the result stays inside `root`: after normalising "
        "`.` and `..`, anything that climbs above the root returns `None`. "
        "`safe_join('/srv/lab', 'a', 'b')` is `/srv/lab/a/b`, and `safe_join('/srv/lab', '../etc')` "
        "is refused.\n\n"
        "**Stretch:** reject absolute components (`/etc/passwd`) as well.",
        "import posixpath\n\ndef safe_join(root, *parts):\n    ...\n",
        "import posixpath\n\ndef safe_join(root, *parts):\n"
        "    for p in parts:\n        if p.startswith('/'):\n            return None\n"
        "    full = posixpath.normpath(posixpath.join(root, *parts))\n"
        "    root_n = posixpath.normpath(root)\n"
        "    if full != root_n and not full.startswith(root_n.rstrip('/') + '/'):\n        return None\n"
        "    return full\n",
        [("a normal join", "safe_join('/srv/lab', 'a', 'b') == '/srv/lab/a/b'", "safe_join('/srv/lab', 'a', 'b')"),
         ("dot segments are normalised", "safe_join('/srv/lab', './a', 'b') == '/srv/lab/a/b'", "safe_join('/srv/lab', './a', 'b')"),
         ("climbing out is refused", "safe_join('/srv/lab', '../etc') is None", "safe_join('/srv/lab', '../etc')"),
         ("deep climb is refused", "safe_join('/srv/lab', '../../etc/passwd') is None", "safe_join('/srv/lab', '../../etc/passwd')"),
         ("absolute component is refused", "safe_join('/srv/lab', '/etc/passwd') is None", "safe_join('/srv/lab', '/etc/passwd')"),
         ("the root itself is fine", "safe_join('/srv/lab', '.') == '/srv/lab'", "safe_join('/srv/lab', '.')")],
        ["`posixpath.normpath` collapses `..` for you — but it can walk out of the root.",
         "Compare with a trailing slash so `/srv/lab-evil` does not pass as `/srv/lab`.",
         "Reject absolute components before joining; `join` would discard the root."],
        stretch="Real check: after opening, ask the OS for the real path and compare."),

    crypto_task(
        "safe-html-escape", "Escape text for an HTML context",
        "Complete `escape_html` so `&`, `<`, `>`, double and single quotes become entities. Order matters: "
        "replace `&` first, or you will double-escape your own entities.\n\n"
        "**Stretch:** escape a complete attribute value including surrounding quotes.",
        "def escape_html(text):\n    ...\n",
        "def escape_html(text):\n    out = str(text).replace('&', '&amp;')\n"
        "    out = out.replace('<', '&lt;').replace('>', '&gt;')\n"
        "    out = out.replace('\"', '&quot;').replace(\"'\", '&#x27;')\n    return out\n",
        [("a tag is neutralised", "escape_html('<script>') == '&lt;script&gt;'", "escape_html('<script>')"),
         ("quotes are escaped", "escape_html('\"') == '&quot;'", "escape_html('\"')"),
         ("ampersand first", "escape_html('&lt;') == '&amp;lt;'", "escape_html('&lt;')"),
         ("plain text is untouched", "escape_html('Marian Nowak') == 'Marian Nowak'", "escape_html('Marian Nowak')"),
         ("an attribute payload dies", "'onerror' in escape_html('\" onerror=alert(1)')", "escape_html('\" onerror=alert(1)')")],
        ["Replace `&` **first**, always. Every other replacement introduces new `&`s.",
         "Escaping is context-specific: this is for HTML text and attributes, not for JS or URLs.",
         "Output encoding beats input filtering — filter what you can, encode the rest."],
        stretch="For a URL in `href`, validate the scheme: `javascript:` is not a URL you can escape away."),

    crypto_task(
        "safe-json-size", "Refuse oversized JSON before parsing",
        "A parser that reads the whole body first is a denial of service waiting to happen. "
        "Complete `safe_loads` so it refuses anything longer than `limit` characters **without "
        "calling `json.loads`**, and returns the parsed object otherwise. Malformed JSON gives "
        "`None`, never an exception.\n\n"
        "**Stretch:** refuse nesting deeper than 20 levels.",
        "import json\n\ndef safe_loads(raw, limit=1024):\n    ...\n",
        "import json\n\ndef safe_loads(raw, limit=1024):\n"
        "    if raw is None or len(raw) > limit:\n        return None\n"
        "    try:\n        return json.loads(raw)\n    except Exception:\n        return None\n",
        [("valid json", "safe_loads('{\"a\": 1}') == {'a': 1}", "safe_loads('{\"a\": 1}')"),
         ("malformed json", "safe_loads('{oops') is None", "safe_loads('{oops')"),
         ("over the limit", "safe_loads('{\"a\": 1}', limit=2) is None", "safe_loads('{\"a\": 1}', limit=2)"),
         ("none input", "safe_loads(None) is None", "safe_loads(None)"),
         ("a list parses", "safe_loads('[1, 2]') == [1, 2]", "safe_loads('[1, 2]')")],
        ["Check the length first — the point is to never hand the bomb to the parser.",
         "`except Exception` around `json.loads` catches `JSONDecodeError` and anything else.",
         "The limit is in characters, not bytes; for bytes, check before decoding."],
        stretch="Bound the nesting too: `json.loads(..., parse_constant=...)` and a depth counter."),

    crypto_task(
        "safe-sql-params", "Build queries that take no user string",
        "Complete `find_user` so it always returns a parameterised query — never string "
        "interpolation. The tests check that a quote in the value stays **inside** the "
        "parameter and does not appear in the SQL text.\n\n"
        "**Stretch:** return the bound values alongside the query so a caller cannot forget them.",
        "def find_user(name):\n    ...\n",
        "def find_user(name):\n"
        "    sql = 'SELECT id, handle FROM users WHERE handle = ?'\n"
        "    return sql, [name]\n",
        [("the query is parameterised", "find_user('kija')[0].count('?') == 1", "find_user('kija')[0]"),
         ("the value is bound, not embedded", "find_user(\"a' OR 1=1 --\")[1] == [\"a' OR 1=1 --\"]", "find_user(\"a' OR 1=1 --\")[1]"),
         ("no quote in the sql text", "'\"' not in find_user(\"a'b\")[0]", "find_user(\"a'b\")[0]"),
         ("the value never reaches the sql text", "'kija' not in find_user('kija')[0]", "find_user('kija')[0]"),
         ("the column list is fixed", "'id, handle' in find_user('kija')[0]", "find_user('kija')[0]")],
        ["`?` placeholders (or `%s` for psycopg) move the data out of the code entirely.",
         "Identifiers cannot be parameterised — table and column names need an allow-list.",
         "Returning the values with the query makes it hard to pass one and forget the other."],
        stretch="The second-order problem: a value stored safely and interpolated later is still unsafe."),

    crypto_task(
        "safe-secret-mask", "Mask secrets before they reach a log",
        "Complete `mask` so it keeps the first and last two characters and replaces everything "
        "between with `*`; anything shorter than 6 characters becomes all stars. Logs outlive "
        "their readers, and a token in a log is a token in everyone's hands.\n\n"
        "**Stretch:** return the length as well, so a reader can spot truncation.",
        "def mask(secret):\n    ...\n",
        "def mask(secret):\n    s = str(secret)\n"
        "    if len(s) < 6:\n        return '*' * len(s)\n"
        "    return s[:2] + '*' * (len(s) - 4) + s[-2:]\n",
        [("a token keeps its ends", "mask('sk_live_abcdefghijkl') == 'sk' + '*' * 16 + 'kl'", "mask('sk_live_abcdefghijkl')"),
         ("short secrets are fully hidden", "mask('abc') == '***'", "mask('abc')"),
         ("six characters keep two", "mask('abcdef') == 'ab**ef'", "mask('abcdef')"),
         ("nothing survives as plain text", "'abcdefghij' not in mask('abcdefghijkl')", "mask('abcdefghijkl')"),
         ("empty stays empty", "mask('') == ''", "mask('')")],
        ["The length must stay constant: a masked value should not leak how long the secret is.",
         "Two stars of head and two of tail is enough to correlate without revealing.",
         "Never log the unmasked value on an error path — that is where secrets escape."],
        stretch="For tokens, keep a short hash instead of the tail: it is correlatable and irreversible."),

    crypto_task(
        "safe-env-parse", "Parse an env file without executing it",
        "Complete `parse_env` so it reads `KEY=value` lines, strips quotes, ignores comments and "
        "blank lines, and never expands `$VAR`. A `.env` file is data, not code — anything that "
        "shells out to read one has a command injection waiting.\n\n"
        "**Stretch:** return a dict where later duplicates win, and keep the first in a `_history` key.",
        "def parse_env(text):\n    ...\n",
        "def parse_env(text):\n    out = {}\n"
        "    for raw in text.splitlines():\n"
        "        line = raw.strip()\n"
        "        if not line or line.startswith('#'):\n            continue\n"
        "        if '=' not in line:\n            continue\n"
        "        key, _, value = line.partition('=')\n"
        "        value = value.strip()\n"
        "        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('\"', \"'\"):\n"
        "            value = value[1:-1]\n"
        "        out[key.strip()] = value\n"
        "    return out\n",
        [("a simple pair", "parse_env('PORT=8080') == {'PORT': '8080'}", "parse_env('PORT=8080')"),
         ("quotes are stripped", "parse_env('NAME=\"anvil lab\"')['NAME'] == 'anvil lab'", "parse_env('NAME=\"anvil lab\"')"),
         ("comments ignored", "parse_env('# c\\nA=1\\n') == {'A': '1'}", "parse_env('# c\\nA=1\\n')"),
         ("no expansion", "parse_env('PATH=$HOME/bin')['PATH'] == '$HOME/bin'", "parse_env('PATH=$HOME/bin')"),
         ("a line without = is skipped", "parse_env('BROKEN') == {}", "parse_env('BROKEN')"),
         ("a value may contain =", "parse_env('URL=http://x/?a=b')['URL'] == 'http://x/?a=b'", "parse_env('URL=http://x/?a=b')")],
        ["`partition('=')` keeps everything after the first `=` inside the value.",
         "Strip quotes only when they match on both ends.",
         "No `os.path.expandvars` — that is exactly the expansion you do not want."],
        stretch="Log the *names* of the keys, never their values, when an env file fails to load."),

    crypto_task(
        "safe-csv-injection", "Neutralise CSV formula injection",
        "A cell starting with `=`, `+`, `-` or `@` is executed by Excel. Complete `safe_cell` so "
        "such values get a leading apostrophe, and nothing else changes.\n\n"
        "**Stretch:** handle tabs and CR inside the cell, which break the quoting.",
        "def safe_cell(value):\n    ...\n",
        "def safe_cell(value):\n    s = str(value)\n"
        "    if s[:1] in ('=', '+', '-', '@'):\n        return \"'\" + s\n"
        "    return s\n",
        [("a formula is defused", "safe_cell('=1+1') == \"'=1+1\"", "safe_cell('=1+1')"),
         ("plus is defused", "safe_cell('+41 22') == \"'+41 22\"", "safe_cell('+41 22')"),
         ("at is defused", "safe_cell('@SUM(A1)') == \"'@SUM(A1)\"", "safe_cell('@SUM(A1)')"),
         ("plain text is untouched", "safe_cell('Marian') == 'Marian'", "safe_cell('Marian')"),
         ("an empty cell stays empty", "safe_cell('') == ''", "safe_cell('')"),
         ("only the first character counts", "safe_cell('a=b') == 'a=b'", "safe_cell('a=b')")],
        ["The check is on the **first** character only — Excel only looks there.",
         "A leading apostrophe is Excel's own escape and stays invisible in the cell.",
         "This is the same class of bug as HTML/CSV injection: the sink decides."],
        stretch="Wrap the field in quotes as well; an apostrophe inside quotes is still needed."),

    crypto_task(
        "safe-subprocess", "Build a command that cannot be hijacked",
        "Complete `cmd` so it returns an argument **list**, never a string. With `shell=False` "
        "(the default) there is no shell to inject into, and a filename with a space stays one "
        "argument.\n\n"
        "**Stretch:** add a check that the executable is on an allow-list.",
        "def cmd(path):\n    ...\n",
        "def cmd(path):\n    return ['/usr/local/bin/anvil-lab', '--path', str(path)]\n",
        [("a list, not a string", "isinstance(cmd('a'), list)", "cmd('a')"),
         ("the executable is fixed", "cmd('x')[0] == '/usr/local/bin/anvil-lab'", "cmd('x')[0]"),
         ("the value is its own argument", "cmd('a b; rm -rf /')[-1] == 'a b; rm -rf /'", "cmd('a b; rm -rf /')[-1]"),
         ("no shell metacharacters are interpreted", "'&&' not in ' '.join(cmd('x'))", "' '.join(cmd('x'))"),
         ("three arguments only", "len(cmd('x')) == 3", "len(cmd('x'))")],
        ["`subprocess.run(['prog', value])` passes the value as one argument — no splitting, no shell.",
         "Never `shell=True` with user input, not even after escaping.",
         "The executable is the first argument and must be a fixed path, not user-supplied."],
        stretch="An allow-list of executables stops a swapped binary from being called at all."),

    crypto_task(
        "safe-retry", "Back off instead of hammering",
        "Complete `should_retry` so it allows attempts 0, 1 and 2, refuses the third, and uses "
        "exponential backoff: `base * 2 ** attempt` seconds, capped at 30. A retry storm against "
        "your own service is how a small outage becomes an incident.\n\n"
        "**Stretch:** return `(ok, delay)` so the caller logs the delay.",
        "def should_retry(attempt, base=1, cap=30):\n    ...\n",
        "def should_retry(attempt, base=1, cap=30):\n"
        "    if attempt >= 3:\n        return False, 0\n"
        "    return True, min(cap, base * (2 ** attempt))\n",
        [("first attempt is allowed", "should_retry(0) == (True, 1)", "should_retry(0)"),
         ("second doubles", "should_retry(1) == (True, 2)", "should_retry(1)"),
         ("third doubles again", "should_retry(2) == (True, 4)", "should_retry(2)"),
         ("fourth is refused", "should_retry(3) == (False, 0)", "should_retry(3)"),
         ("the cap holds", "should_retry(2, base=100)[1] == 30", "should_retry(2, base=100)"),
         ("base is configurable", "should_retry(1, base=5) == (True, 10)", "should_retry(1, base=5)")],
        ["`base * (2 ** attempt)` is the whole formula.",
         "`min(cap, ...)` stops the delay from growing without bound.",
         "A refused retry returns delay 0 so the caller has one code path."],
        stretch="Add jitter: full synchronisation of retries is its own outage mode."),
]

# ==================================================================== quizy
QUIZZES = [
    quiz("quiz-rust-move-vec", "rust", "Predict the output: moving out of a Vec",
          "Which program **compiles**?\n\n```\nfn main() {\n    let v = vec![1, 2, 3];\n    let first = &v[0];\n    println!(\"{}\", first);\n    v.push(4);\n    println!(\"{:?}\", v);\n}\n```",
          ["It does not compile: `first` borrows `v`, and `v.push` needs a mutable borrow (E0502)",
           "It compiles and prints `[1, 2, 3, 4]`",
           "It compiles but prints the old contents, because `push` reallocates",
           "It compiles only with `let first = v[0]` instead of `&v[0]`"],
          [0],
          "E0502: a shared borrow is still alive at `println!`, and `push` needs `&mut v`. "
          "Copy the value out (`v[0]` is `i32`, so it is `Copy`) and the borrow ends immediately. "
          "This is the borrow checker earning its keep — the same code in C++ is a use-after-realloc waiting to happen."),

    quiz("quiz-rust-arc", "rust", "Predict the output: Rc, RefCell and interior mutability",
          "Which statement about `Rc<RefCell<i32>>` is true?\n\n```\nuse std::cell::RefCell;\nuse std::rc::Rc;\nlet a = Rc::new(RefCell::new(1));\nlet b = a.clone();\n*b.borrow_mut() += 1;\nprintln!(\"{}\", a.borrow());\n```",
          ["It prints `2`: `Rc` clones share one value and `borrow_mut` mutates it",
           "It does not compile — `Rc` is not `Clone`",
           "It prints `1`: the clone is a deep copy",
           "It panics with a borrow error at `borrow_mut`"],
          [0],
          "`Rc<T>` is a reference-counted pointer: cloning shares, and the value is dropped when the last handle goes. "
          "`RefCell` moves the borrow rules to runtime, which is why `borrow_mut` returns a guard that can panic. "
          "Note the runtime cost — `Rc` is not thread-safe; that is `Arc<Mutex<_>>`."),

    quiz("quiz-rust-lifetime-fn", "rust", "Predict the output: lifetime elision",
          "Which signature is equivalent to what the compiler actually desugars?\n\n```\nfn first_word(s: &str) -> &str\n```",
          ["`fn first_word<'a>(s: &'a str) -> &'a str` — one input lifetime, so the output borrows from it",
           "`fn first_word<'a, 'b>(s: &'a str) -> &'b str` — two independent lifetimes",
           "`fn first_word(s: &str) -> &'static str` — elision picks `'static`",
           "It does not compile without explicit lifetimes"],
          [0],
          "Elision rule 2: exactly one input lifetime means the output gets it. The compiler writes "
          "`fn first_word<'a>(s: &'a str) -> &'a str`. Write it out when a signature has more than one "
          "input lifetime and elision can no longer help."),

    quiz("quiz-rust-trait-obj", "rust", "Predict the output: dynamic dispatch",
          "What does this print?\n\n```\ntrait Speak { fn hello(&self) -> String; }\nstruct Dog;\nimpl Speak for Dog { fn hello(&self) -> String { \"woof\".into() } }\nfn main() { let s: Box<dyn Speak> = Box::new(Dog); println!(\"{}\", s.hello()); }\n```",
          ["`woof` — `Box<dyn Speak>` is a trait object, dispatched at run time",
           "Nothing — trait objects need a generic bound",
           "`woof` plus a warning about unsized types",
           "It does not compile: `Dog` must implement `Sized`"],
          [0],
          "`dyn Trait` is a fat pointer: a value plus a vtable of method pointers. The call is dispatched "
          "dynamically, so it costs one indirect jump. `Box<dyn Trait>` owns the value; `&dyn Trait` borrows it."),

    quiz("quiz-rust-unsafe", "rust", "Predict the output: unsafe blocks",
          "What is wrong with this?\n\n```\nlet mut v = vec![1];\nunsafe { v.push(2); }\nprintln!(\"{:?}\", v);\n```",
          ["Nothing — `push` is safe, the block is merely unnecessary",
           "Nothing is wrong, but an `unsafe` block disables borrow checking for its whole body",
           "It does not compile — `unsafe` is not allowed in `main`",
           "`v` must be declared `mut unsafe`"],
          [0],
          "`unsafe` only unlocks the five things Rust otherwise forbids: dereferencing a raw pointer, calling an unsafe "
          "function, mutating a static, accessing a union field, implementing an unsafe trait. Everything else inside "
          "still has to be correct by hand — which is exactly why the block here buys nothing."),

    quiz("quiz-rust-iterator", "rust", "Predict the output: iterator laziness",
          "What does this print?\n\n```\nlet v = vec![1, 2, 3];\nlet sum: i32 = v.iter().map(|x| x * 2).filter(|x| *x > 2).sum();\nprintln!(\"{}\", sum);\n```",
          ["`8` — only `2` and `3` survive the filter, doubled to 4 and 6",
           "`12` — every element is doubled and summed",
           "`0` — `sum()` on a lazy iterator always starts at zero",
           "It does not compile: `map` needs a closure type annotation"],
          [0],
          "Iterators are lazy: `map` and `filter` build a chain, `sum` is what pulls it. "
          "1→2 (filtered out), 2→4, 3→6, total 10... except the filter keeps `x > 2` **after** doubling, "
          "so 2 and 4 survive: 4 + 4 = 8. Order matters — that is the lesson of this one."),

    quiz("quiz-rust-error", "rust", "Predict the output: Result vs Option",
          "Which is idiomatic for `fn find(id: u32) -> Option<User>` when the caller must explain a failure?\n\n"
          "```rust\nlet user = find(7)?;\n```",
          ["`Option` — `?` propagates `None` and works in a function returning `Option`",
           "`Result` — missing data is an error that must carry a message",
           "Both compile, but `Result` is preferred by clippy",
           "Neither — `?` only works with `Result`"],
          [0],
          "`?` works with both, propagating `None` or `Err`. The choice is semantic: a missing optional value is an "
          "`Option`; a failure with a reason is a `Result`. The difference shows up in the type signature — a caller "
          "cannot ignore an error message by accident."),

    quiz("quiz-py-gil", "python", "Why the GIL matters in CPython",
          "What does the Global Interpreter Lock prevent in CPython 3.12?\n\n```python\nfrom concurrent.futures import ProcessPoolExecutor\nwith ProcessPoolExecutor() as ex:\n    list(ex.map(cpu_bound, items))\n```",
          ["Two threads executing Python bytecode at the same instant in one process",
           "Two processes from different users sharing a file",
           "Extension modules being loaded twice",
           "The garbage collector running during a thread switch"],
          [0],
          "The GIL serialises bytecode execution inside one process, so two threads never run Python code simultaneously. "
          "CPU-bound work must go to processes (`ProcessPoolExecutor`) or a native library that releases the GIL "
          "(`hashlib`, `zlib`, `numpy`). I/O-bound work is unaffected — threads are fine there."),

    quiz("quiz-py-mutable-default", "python", "Python gotchas: mutable default arguments",
          "What does this print on the **third** call?\n\n```python\ndef append(item, bucket=[]):\n    bucket.append(item)\n    return bucket\nappend(1); append(2); print(append(3))\n```",
          ["`[1, 2, 3]` — the default list is created once and shared between calls",
           "`[3]` — the default is rebuilt each call",
           "`[3, 3]` — `item` is appended twice",
           "It raises `TypeError`"],
          [0],
          "Defaults are evaluated **once**, when the `def` runs, so the same list object is reused. It survives "
          "because the list is mutated, not rebound. The fix is `bucket=None` then `bucket = [] if bucket is None else bucket`."),

    quiz("quiz-py-lazy", "python", "Python gotchas: generators and laziness",
          "What does this print?\n\n```python\ndata = (x * x for x in range(5))\nprint(next(data), list(data))\n```",
          ["`0 [1, 4, 9, 16]` — the generator resumes where it stopped",
           "`0 [0, 1, 4, 9, 16]` — a second list starts from scratch",
           "`0 []` — generators are consumed by the first `next`",
           "`None [0, 1, 4, 9, 16]`"],
          [0],
          "A generator keeps its position. `next()` took `0`, so `list()` continues from `1` to `16`. "
          "That single fact is what makes streaming parsers work — and what makes them dangerous when you iterate twice."),

    quiz("quiz-py-context", "python", "Python gotchas: context managers",
          "What does `with open(path) as f:` guarantee when an exception happens inside the block?",
          ["`f.close()` runs, then the exception propagates",
           "The file is closed only if the block completes normally",
           "`f.close()` runs and the exception is swallowed",
           "Nothing — `with` is only a readability aid"],
          [0],
          "`with` calls `__exit__` on the way out, exception or not. That is what guarantees a file handle or a lock "
          "is released. `contextlib.suppress` is the tool when you *do* want to swallow the exception."),

    quiz("quiz-sec-tls", "security", "TLS: what the certificate actually proves",
          "A TLS certificate proves that the holder controls the key for that name. What does it **not** prove?",
          ["That the server is honest — anyone who bought a certificate for a domain has it",
           "That the certificate has not expired",
           "That the private key matches the certificate",
           "That the chain terminates in a root the client trusts"],
          [0],
          "That is the whole point of an *extended* validation debate: a cheap DV certificate means only "
          "'someone proved control of the domain'. The protocol protects the channel from passive and active "
          "attackers against the endpoint — not against the endpoint itself."),

    quiz("quiz-sec-jwt", "security", "JWT: where the signature has to be checked",
          "A service reads `payload.role` from a JWT. Where must the signature be verified?",
          ["Before trusting any claim — the payload is base64, not encrypted, so anyone can edit it",
           "Only on the login endpoint; afterwards the session is trusted",
           "Only when the token contains a `role` claim",
           "In the client — the API trusts signed tokens by definition"],
          [0],
          "The payload is just base64: anyone can craft `{\"role\":\"admin\"}` and base64 it. "
          "Verify the signature and check `alg`, `exp`, `iss` and `aud` **before** reading a single claim. "
          "This is exactly what the `alg: none` lab shows."),

    quiz("quiz-sec-hash", "security", "Hashing: password vs checksum",
          "Why are SHA-256 and bcrypt not interchangeable for passwords?",
          ["SHA-256 is fast, so a GPU tries billions of candidates per second; bcrypt is deliberately slow",
           "SHA-256 cannot hash passwords, only files",
           "bcrypt adds a salt automatically, SHA-256 does not",
           "SHA-256 is broken for short inputs"],
          [0],
          "Speed is the enemy for password hashes. bcrypt, scrypt and Argon2 are tuned so each guess costs "
          "milliseconds on the attacker's GPU as well as yours. A fast hash is fine for integrity checks — "
          "where the attacker cannot submit candidates."),

    quiz("quiz-sec-perm", "security", "Linux: what 0777 really means",
          "A service runs as root with `chmod 777 /var/lib/anvil`. What is the practical risk?",
          ["Any local user can replace files the service trusts — privilege escalation, not just disclosure",
           "Only the owner loses write access, which is fine",
           "The service can no longer start",
           "Nothing — the kernel ignores permissions for root-owned files"],
          [0],
          "World-writable state that a privileged process trusts is a straight path to root: replace a script, a "
          "config or a library the service loads at startup. Least privilege (`0750`, a dedicated user, "
          "a read-only mount) is the fix."),

    quiz("quiz-sec-suid", "security", "Linux: setuid binaries",
          "Why is `chmod u+s` on a shell script useless, and on a binary dangerous?",
          ["The kernel ignores the setuid bit on scripts; on binaries it runs the program as the file owner",
           "Scripts cannot hold the setuid bit at all, and binaries lose it on update",
           "Both work the same way",
           "setuid only affects read permissions"],
          [0],
          "The kernel ignores setuid on interpreted files precisely because the interpreter would run as root. "
          "On a binary it grants the owner's privileges — which is why every SUID binary in `/usr/bin` is a "
          "hardening target and why `nosuid` exists as a mount option."),

    quiz("quiz-sec-sqli-blind", "security", "SQL injection: blind time-based",
          "`GET /item?id=1 AND SLEEP(5)` returns in 5 seconds, while `id=2` returns instantly. What happened?",
          ["The `AND SLEEP(5)` was evaluated by the database and delayed the response — blind injection",
           "The web server was overloaded",
           "The query was cached and timed out",
           "The parameter was parsed as an integer and rejected"],
          [0],
          "The application's filter only knew about `' OR`, so the payload went through. No data came back — "
          "only timing — which is enough to exfiltrate a database one bit at a time. This is why parameterised "
          "queries are the only real fix: filters are guesses, parameters are a contract."),

    quiz("quiz-sec-xss-context", "security", "XSS: why context matters",
          "Where is `<script>alert(1)</script>` in `href=\"javascript:...\"` escaped automatically?",
          ["In HTML attribute context you must escape quotes; in `<script>` you must not HTML-escape at all",
           "Browsers escape all contexts automatically",
           "It is escaped in both, so neither is dangerous",
           "Only in JSON responses"],
          [0],
          "Escaping is context-specific: HTML text, HTML attribute, JS string, URL and CSS each need different "
          "treatment — and escaping JS inside `<script>` with `&lt;` does nothing. That is why templating engines "
          "track the context for you and raw-HTML helpers are dangerous."),

    quiz("quiz-sec-csrf", "security", "CSRF: why SameSite helps but does not finish it",
          "A session cookie with `SameSite=Lax` blocks cross-site POSTs. Why is CSRF still possible?",
          ["Older browsers ignore it, and GET-based state changes are still sent on top-level navigation",
           "It does not work at all",
           "Only for HTTPS sites",
           "Because CSRF needs the cookie to be sent cross-origin"],
          [0],
          "`SameSite=Lax` still allows top-level GET navigations, so any state change reachable by GET stays exploitable. "
          "The remaining defences: make every state change a non-GET, add a CSRF token, and check `Origin`/`Referer`."),

    quiz("quiz-sec-ssrf", "security", "SSRF: why a blocklist of hosts is not enough",
          "A fetcher blocks `127.0.0.1` and `localhost`. What still works?",
          ["`0x7f.0.0.1`, `0177.0.0.1`, `[::1]`, a DNS name that resolves to a private address, and a redirect to one",
           "Nothing — the blocklist is complete",
           "Only IPv6 loopback",
           "Only when the URL uses a port above 1024"],
          [0],
          "Alternate encodings, IPv6, DNS rebinding and HTTP redirects all get you to the same host. "
          "The durable fixes are an allow-list of destinations and egress filtering at the network layer — "
          "plus disabling redirect following."),

    quiz("quiz-sec-headers", "security", "Response headers that actually matter",
          "Which header set is the closest to correct for a JSON API?",
          ["`Content-Type: application/json`, `X-Content-Type-Options: nosniff`, a CSP, `frame-ancestors 'none'`, HSTS",
           "`Content-Type: text/html` and nothing else",
           "`Access-Control-Allow-Origin: *` with a session cookie",
           "Only `Server: nginx`"],
          [0],
          "`nosniff` stops browsers from re-interpreting JSON as HTML, a CSP with `default-src 'none'` closes "
          "everything you did not list, `frame-ancestors` blocks clickjacking and HSTS pins the scheme. "
          "Note this lab runs with exactly that policy — a closed CSP is why Python has to be vendored."),

    quiz("quiz-sec-logging", "security", "Logging: what not to write",
          "Which line is safe to log at `info`?",
          ["`auth failed for user=kija from=10.0.0.7`",
           "`password for kija is Anvil2026!`",
           "`session token sk_live_9f3c…` accepted",
           "`SELECT * FROM users WHERE password LIKE '%anvil%'`"],
          [0],
          "Passwords, tokens and raw queries all put a credential or a query shape into a log that outlives "
          "its readers. Log the outcome and the actor; keep the secret masked, or not at all."),

    quiz("quiz-sec-race", "security", "Race conditions: TOCTOU",
          "`if os.path.exists(p): open(p)` — what is the race?",
          ["Between the check and the open, another process can replace `p` — classic time-of-check to time-of-use",
           "`exists` is slow on network filesystems",
           "The file may be larger than expected",
           "There is no race on a local filesystem"],
          [0],
          "TOCTOU is the shape of half the local privilege escalations: check, then act. Fixes are `O_EXCL`, "
          "`O_NOFOLLOW`, or doing the check *inside* the operation with a syscall that fails atomically."),

    quiz("quiz-ruby-block", "ruby", "Ruby: what `&:sym` does",
          "What does `[1, 2, 3].map(&:to_s)` return?",
          ["`['1', '2', '3']` — `&:sym` converts the symbol into a proc",
           "It raises: `&` only takes a block",
           "`[:to_s]` — it collects the symbols",
           "`[1, 2, 3]` — it is a no-op"],
          [0],
          "`&:sym` is `Symbol#to_proc` — it builds a proc that calls the method on each argument. "
          "The same trick is `map { |x| x.upcase }` versus `map(&:upcase)`, and it is why Ruby code reads "
          "as a pipeline."),

    quiz("quiz-ruby-frozen", "ruby", "Ruby: string mutation surprises",
          "What does this print?\n\n```ruby\ndef tag(name)\n  name << \"-prod\"\nend\na = \"lab\"\ntag(a)\nputs a\n```",
          ["`lab-prod` — `<<` mutates the caller's string in place",
           "`lab` — the method works on a copy",
           "`-prod` — `<<` returns the appended part",
           "It raises `FrozenError`"],
          [0],
          "Ruby passes references, so `<<` (and `gsub!`, `upcase!`) mutate the argument the caller still holds. "
          "`+` and non-bang methods return new objects. Freezing literals or using `dup` at the boundary "
          "keeps surprises out of production."),

    quiz("quiz-net-dns", "security", "DNS: what a stale record costs you",
          "A decommissioned host's DNS record still resolves. What is the security consequence?",
          ["Anyone who can claim the IP now receives traffic intended for your old service",
           "Nothing — the TTL handles it",
           "The certificate stops working immediately",
           "Queries to that name fail"],
          [0],
          "A stale A/AAAA record is a subdomain takeover waiting to happen: if the address returns to a shared pool "
          "or is sold, your hostname now points at someone else's server — cookies scoped to the domain and any "
          "client trusting the name are exposed. Delete the record the day you decommission."),

    quiz("quiz-net-tls-downgrade", "security", "TLS: what a downgrade looks like",
          "What does a network attacker gain by forcing TLS 1.0 instead of 1.3?",
          ["Weaker cipher suites and no forward secrecy — long-term key compromise can decrypt old traffic",
           "Nothing — TLS 1.0 is still encrypted",
           "They can read only the certificate",
           "The session cookie becomes readable"],
          [0],
          "TLS 1.3 removed RSA key exchange and static ciphers precisely because of traffic analysis and "
          "long-term key compromise. Forcing an older version reintroduces both, so the version itself must be "
          "pinned — that is what HSTS plus a minimum version does."),

    quiz("quiz-obs-logging", "security", "eBPF: what it can and cannot see",
          "An eBPF probe attached to a syscall sees the arguments the kernel passes. What can it never see?",
          ["Userspace memory contents beyond what a copy helper explicitly reads",
           "The syscall number",
           "The process pid",
           "The return value"],
          [0],
          "`bpf_probe_read_user` copies explicitly — the probe has no view of arbitrary memory. That is a "
          "deliberate boundary: a probe cannot leak data it was not asked to copy, which is why wrapping it "
          "correctly is the whole exercise in the `rs-l1-ffi` lab."),

    quiz("quiz-proc-fd", "security", "Linux: reading a process's secrets",
          "Where do you find environment variables of a running process, and why does that matter?",
          ["`/proc/<pid>/environ` — any user who can read it gets the process's secrets",
           "`/proc/<pid>/cmdline` — arguments are always secret-free",
           "`/var/log/syslog` — the kernel logs env changes",
           "There is no such interface"],
          [0],
          "`environ` is readable when file permissions allow it, and it is a favourite post-exploitation step. "
          "`cmdline` is visible to every user via `ps` — which is why secrets belong in files with tight modes "
          "or a secret store, never in argv."),

    quiz("quiz-git-history", "security", "Git: a secret in history",
          "A token was committed and then `git commit --amend` removed it. Is the repository safe to publish?",
          ["No — the old object is still in history and reachable via reflog or any existing clone",
           "Yes — amend rewrites the object entirely",
           "Yes, as long as nothing was pushed",
           "No, but only for HTTPS remotes"],
          [0],
          "Amend creates a new commit; the old one stays in the object database until garbage collection, and every "
          "existing clone still has it. Real fixes: rotate the credential first, then `git filter-repo` (or BFG) "
          "and force-push, and assume anything ever pushed was public."),

    quiz("quiz-container-escape", "security", "Containers: what the isolation really is",
          "A container gives you namespaces and cgroups. What does it **not** provide?",
          ["A separate kernel — a kernel bug reaches the host from any container",
           "Process isolation",
           "Filesystem isolation",
           "Resource limits"],
          [0],
          "Containers share the host kernel, so a kernel vulnerability or a badly configured device mount is a host "
          "compromise. Namespaces and cgroups contain mistakes, not attackers with a kernel exploit — which is why "
          "sandboxed builds, seccomp and rootless mode matter."),

    quiz("quiz-crypto-random", "security", "Randomness: where not to use `random`",
          "Where does using a non-cryptographic RNG actually break something?",
          ["Session tokens, password resets, key generation — anything an attacker can predict",
           "Sorting a list",
           "Generating a UUID for analytics",
           "Choosing a random test fixture"],
          [0],
          "A predictable `random` output is a session hijack: the attacker enumerates. Use `secrets` in Python, "
          "`crypto/rand` in Go, `os.urandom` anywhere else. Plain `random` is fine for shuffling a UI."),

    quiz("quiz-log-forgery", "security", "Logs: log forging vs log injection",
          "Why is stripping `\\n` from a log value not enough?",
          ["An attacker can still write misleading records with control characters your terminal renders",
           "Because `\\n` is the only dangerous character",
           "Because stripping changes the value",
           "It is enough"],
          [0],
          "Terminal escape sequences, bidi overrides and zero-width characters can all rewrite what a human reads. "
          "Encode the value in the log format (JSON, structured fields) rather than trying to sanitise free text."),

    quiz("quiz-api-ratelimit", "security", "Rate limiting: client vs server",
          "A client sends `X-RateLimit-Remaining: 0` and stops calling. What is wrong?",
          ["The client is untrusted — limits must be enforced server-side, per identity, not per header",
           "Nothing, headers are authoritative",
           "The header should be in the response, not the request",
           "It only works over HTTP/2"],
          [0],
          "Anything the client controls is decoration. Enforce on the server, keyed by something the client cannot "
          "forge alone (an authenticated identity, an address you have some reason to trust), and return the "
          "headers as information, not as control."),
]

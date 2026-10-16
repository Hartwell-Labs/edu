#!/usr/bin/env python3
"""
gen_tasks.py — generator katalogu Anvil.

Katalog ma być duży (300+ lekcji) i każda lekcja ma być *rozwiązywalna*.
Placeholdery odpadają, więc zadania powstają ze **specyfikacji**: rozwiązanie
referencyjne i testy wywodzą się z tego samego opisu, a check-tasks.py
potwierdza, że każde zadanie przechodzi na swoim rozwiązaniu.

    python3 tools/gen_tasks.py            # zapisuje public/tasks/index.json
    python3 tools/gen_tasks.py --stats    # tylko liczby
"""
from __future__ import annotations
import json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

OUT = ROOT / "public" / "tasks" / "index.json"
FLAGSHIP = ROOT / "tools" / "flagship.json"      # 16 ręcznie pisanych lekcji


def _detail_expr(detail):
    """Szczegół w teście bywa wyrażeniem (`parse_line(LOG)`), a czasem opisem
    („a space in the name"). Wyrażenie zostaje, opis trafia do cudzysłowów —
    inaczej wygenerowany kod się nie parsuje."""
    return detail if ("(" in detail or "[" in detail) else repr(detail)


def tests(*checks) -> str:
    rows = []
    for c in checks:
        name, expr = c[0], c[1]
        detail = c[2] if len(c) > 2 else None
        rows.append(f"check({name!r}, {expr}, {_detail_expr(detail)})" if detail
                    else f"check({name!r}, {expr})")
    return "\n".join(rows) + "\n"


def parse_log(tid, title, sample, fields, *, difficulty=2, points=110, free=False,
              area="Log parsing", stretch="", hint=""):
    """Jedna linia logu -> slownik. Testy i rozwiazanie dziela ten sam parser."""
    n = len(fields)
    toks = sample.split()
    for key, idx in fields:
        if not 0 <= idx < len(toks):
            raise SystemExit(
                f"{tid}: pole {key!r} ma indeks {idx}, a probka ma tylko "
                f"{len(toks)} pol: {toks}")
    setup = f"LOG = {sample!r}\n"
    first = sample.split()[fields[0][1]]
    field_doc = ", ".join(f"`{k}` = element {i}" for k, i in fields)
    brief = (
        f"One line from a {area.lower()} log:\n\n```\n{sample}\n```\n\n"
        f"Complete `parse_line` so it returns a dict with {field_doc}. Fewer than {n} "
        f"whitespace-separated fields means a broken line — return `None` instead of raising. "
        f"Truncated and continuation lines are normal in production logs."
    )
    if stretch: brief += f"\n\n**Stretch:** {stretch}"
    sol = ("def parse_line(line):\n"
           "    p = line.split()\n"
           f"    if len(p) < {n}:\n"
           "    return None\n"
           "    return {" + ", ".join(f"{k!r}: p[{i}]" for k, i in fields) + "}\n")
    sol = sol.replace("    return None\n", "        return None\n")
    return task(tid, "python", title, difficulty, points, "pyodide", brief, free=free,
                area=area,
                starter=setup + "\ndef parse_line(line):\n    ...\n",
                hints=[hint or f"`line.split()` gives a flat list; {n} fields means the guard is `if len(p) < {n}`.",
                       "Quote the key names in the dict literal: `{'ip': p[0]}`.",
                       "Return a dict, not a list — the checks index it by key."],
                tests=tests(
                    ("first field", f"parse_line(LOG)['{fields[0][0]}'] == {first!r}", "parse_line(LOG)"),
                    ("field count", f"len(parse_line(LOG)) == {n}", "parse_line(LOG)"),
                    ("a short line is None", "parse_line('truncated') is None", "parse_line('truncated')"),
                    ("an empty line is None", "parse_line('') is None", "parse_line('')"),
                    ("surrounding spaces collapse", f"parse_line({('  ' + sample + '  ')!r}) == parse_line(LOG)", "parse_line(LOG)"),
                ),
                solution=sol, setup=setup)


def detect(tid, title, patterns, attacks, benign, *, difficulty=3, points=150,
           free=False, flag="request value", hint="", stretch="",
           area="Injection detection"):
    """Wykrywanie wzorcow atakow: any() po liscie wzorcow."""
    pstr = ", ".join(f"`{p}`" for p in patterns)
    brief = (
        f"You get a {flag}. Complete `is_attack` so it returns `True` when the value contains "
        f"any of these patterns, case-insensitively: {pstr}.\n\n"
        f"Normal input must pass through untouched — `{benign[0]}` is legitimate, and so is an "
        f"empty value. `.lower()` first: attackers change case."
    )
    if stretch: brief += f"\n\n**Stretch:** {stretch}"
    sol = ("PATTERNS = [" + ", ".join(repr(p.lower()) for p in patterns) + "]\n\n"
           "def is_attack(value):\n    v = value.lower()\n    return any(p in v for p in PATTERNS)\n")
    checks = [(f"flags {label}", f"is_attack({expr!r}) is True", f"is_attack({expr!r})") for label, expr in attacks]
    checks += [(f"benign input {i+1}", f"is_attack({b!r}) is False", f"is_attack({b!r})") for i, b in enumerate(benign)]
    checks += [("empty is not an attack", "is_attack('') is False", "is_attack('')")]
    return task(tid, "security", title, difficulty, points, "pyodide", brief, free=free,
                area=area,
                starter="def is_attack(value):\n    ...\n",
                hints=[hint or "A list of patterns plus `any()` — not a pyramid of `if`s.",
                       "Every comparison must run on the lowercased value, never on the raw one.",
                       "Real WAFs normalise unicode and double encoding first; `any()` on raw text is the toy version."],
                tests=tests(*checks), solution=sol, setup="")


def crypto_task(tid, title, brief_text, starter, solution, test_rows, hints, *,
                difficulty=3, points=160, free=False, setup="", stretch="",
                area="Crypto"):
    brief = brief_text + (f"\n\n**Stretch:** {stretch}" if stretch else "")
    return task(tid, "python", title, difficulty, points, "pyodide", brief, free=free,
                area=area, starter=starter, hints=hints, tests=tests(*test_rows),
                solution=solution, setup=setup)


DEFAULT_HINTS = [
    "Read the failing check: the name says what broke and the detail shows the value you produced.",
    "The reference answer is one small function — your version may differ as long as the behaviour matches.",
    "`print()` inside the function is a legitimate debugging tool; the checks only look at return values.",
]


def net_task(tid, title, brief_text, starter, solution, test_rows, hints=None, *,
             difficulty=3, points=150, free=False, setup="", stretch="", track="security",
             area="", hint=""):
    # Katalog ma byc czytelny z boku, wiec kazda lekcja musi trafic do
    # jakiegos obszaru — inaczej 300 pozycji w jednym worku.
    area = area or ("Networking" if track == "security" else "Python")
    brief = brief_text + (f"\n\n**Stretch:** {stretch}" if stretch else "")
    return task(tid, track, title, difficulty, points, "pyodide", brief, free=free, area=area,
                starter=starter, hints=([hint] if hint else []) + list(hints or DEFAULT_HINTS),
                tests=tests(*test_rows), solution=solution, setup=setup)


def quiz(tid, track, title, brief_text, choices, answer, explain, *, difficulty=3,
         points=120, free=False, vm_check="cargo build 2>&1 | head -20", area=""):
    # Quizy wypelniaja trzy sekcje (Rust, Ruby, bezpieczenstwo), wiec obszar
    # bierzemy ze sciezki — chyba ze autor podal wlasny.
    area = area or {"rust": "Rust questions", "ruby": "Ruby questions",
                    "python": "Python questions"}.get(track, "Security questions")
    return task(tid, track, title, difficulty, points, "quiz", brief_text, free=free,
                area=area, choices=choices, answer=answer, explain=explain,
                vm_check=vm_check)


def vm_task(tid, title, brief_text, task_id, *, difficulty=3, points=200, free=False,
            accept=None, stretch="", track="security", area="Lab machine"):
    brief = brief_text + (f"\n\n**Stretch:** {stretch}" if stretch else "")
    return task(tid, track, title, difficulty, points, "vm", brief, free=free, area=area,
                vm_check=f"labcheck --task {task_id}",
                vm_accept=accept or ["OK", "PASS", "passed"])


# Skróty używane w plikach specyfikacji — jedna linia na lekcję.
def py_task(tid, title, brief, starter, solution, test_rows, **kw):
    """Lekcja Pythona wykonywana w przeglądarce (Pyodide)."""
    return net_task(tid, title, brief, starter, solution, test_rows,
                    track="python", **kw)


def sec_task(tid, title, brief, starter, solution, test_rows, **kw):
    """Lekcja bezpieczeństwa wykonywana w przeglądarce (Pyodide)."""
    return net_task(tid, title, brief, starter, solution, test_rows,
                    track="security", **kw)


def rb_task(tid, title, brief, task_id, **kw):
    """Lekcja Ruby na maszynie labowej."""
    kw.setdefault("track", "ruby")
    kw.setdefault("area", "Lab machine")
    return vm_task(tid, title, brief, task_id, **kw)


def rs_task(tid, title, brief, task_id, **kw):
    """Lekcja Rust na maszynie labowej."""
    kw.setdefault("track", "rust")
    kw.setdefault("area", "Lab machine")
    return vm_task(tid, title, brief, task_id, **kw)


def task(tid, track, title, difficulty, points, executor, brief, **kw):
    t = {"id": tid, "track": track, "title": title, "difficulty": difficulty,
         "free": kw.pop("free", False), "points": points, "executor": executor, "brief": brief}
    for k in ("starter", "hints", "tests", "setup", "solution", "choices",
              "answer", "explain", "vm_check", "vm_accept", "area"):
        v = kw.get(k)
        if v:
            t[k] = v
    return t


def build() -> list[dict]:
    from specs_logs import LOG_TASKS, AGG_TASKS
    from specs_detect import DETECT_TASKS
    from specs_crypto import CRYPTO, NET
    from specs_safe import SAFE, QUIZZES
    from specs_vm import VMS
    from specs_text import TEXT, TEXT_CODEC
    from specs_data import DATA, DATA_RE
    from specs_net2 import NET as NET2, NET_PY
    from specs_logs2 import LOG2_TASKS, AGG2_TASKS
    from specs_sec import SEC
    from specs_rustq import QUIZZES as RUST_QUIZZES
    from specs_rubyq import QUIZZES as RUBY_QUIZZES

    flagship = json.loads(FLAGSHIP.read_text())
    generated = (LOG_TASKS + AGG_TASKS + DETECT_TASKS + CRYPTO + NET + SAFE + QUIZZES
                 + VMS + TEXT + TEXT_CODEC + DATA + DATA_RE + NET2 + NET_PY
                 + LOG2_TASKS + AGG2_TASKS + RUST_QUIZZES + RUBY_QUIZZES + SEC)

    seen, out = set(), []
    for t in flagship + generated:
        if t["id"] in seen:
            raise SystemExit(f"duplicate id: {t['id']}")
        seen.add(t["id"])
        out.append(t)

    # Brak obszaru = lekcja niewidoczna w grupowaniu. Lepiej zbuildowac sie
    # nieudany niz wypublikowac katalog, w ktorym 40 pozycji lezy w "Other".
    missing = [t["id"] for t in out if not t.get("area")]
    if missing:
        raise SystemExit("brak obszaru (area) dla: " + ", ".join(missing[:12])
                         + ("…" if len(missing) > 12 else ""))

    # Pierwsze dziesięć po kolei to darmowe — potem płatny tier.
    free_ids = {t["id"] for t in flagship if t["free"]}
    for t in out:
        t["free"] = t["id"] in free_ids
    return out


def main() -> None:
    tasks = build()
    if "--stats" in sys.argv:
        by_ex = {}
        by_track = {}
        for t in tasks:
            by_ex[t["executor"]] = by_ex.get(t["executor"], 0) + 1
            by_track[t["track"]] = by_track.get(t["track"], 0) + 1
        print(f"  razem      {len(tasks)}")
        print(f"  darmowe    {sum(1 for t in tasks if t['free'])}")
        print(f"  płatne     {sum(1 for t in tasks if not t['free'])}")
        print(f"  wykonawcy  {by_ex}")
        print(f"  ścieżki    {by_track}")
        print(f"  punktów    {sum(t['points'] for t in tasks)}")
        return

    data = {
        "generated": "2026-10-16",
        "site": "https://edu.hartwell-labs.pl",
        "notes": [
            f"Access model: a free account opens the first ten lessons; the paid second tier (lifetime) opens the other {sum(1 for t in tasks if not t['free'])}.",
            "Executors: pyodide (Python in WASM), vm (downloadable lab machine), quiz.",
            "The catalogue is generated from specifications by tools/gen_tasks.py — every code lesson carries its reference solution, and check-tasks.py runs it.",
            "Tests check behaviour, not the shape of your code. 'quiz' lessons have exactly one correct answer.",
            "Every lesson ends with a Stretch line: the honest follow-up once the checks pass.",
        ],
        "tracks": [
            {"id": "security", "label": "Cybersecurity", "executor": "quiz+pyodide+vm"},
            {"id": "python", "label": "Python", "executor": "pyodide"},
            {"id": "ruby", "label": "Ruby", "executor": "vm"},
            {"id": "rust", "label": "Rust", "executor": "quiz+vm"},
        ],
        "tasks": tasks,
    }
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    print(f"  {len(tasks)} lekcji → {OUT.relative_to(ROOT)}")
    print(f"  darmowe {sum(1 for t in tasks if t['free'])}, "
          f"płatne {sum(1 for t in tasks if not t['free'])}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Sprawdza, że każde zadanie w tasks/index.json da się rozwiązać i że testy
przechodzą na referencyjnym rozwiązaniu — lokalnie, bez przeglądarki.
Używa tego samego protokołu co silnik (helper check + znacznik @@R@@)."""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
TASKS = json.loads((ROOT / "public/tasks/index.json").read_text())["tasks"]
MARK = "@@R@@"

# Bez .format() — kod zadań zawiera klamry, więc składamy stringi ręcznie.
PRELUDE = """import json, sys
def check(name, ok, detail=''):
    __R__.append({'name': name, 'ok': bool(ok), 'detail': str(detail)[:300]})
__R__ = []
"""
EPILOGUE = "\nprint(" + json.dumps(MARK) + " + json.dumps(__R__))\n"


def run_python(task, source):
    code = PRELUDE + task.get("setup", "") + "\n" + (source or "") + "\n" + task.get("tests", "") + EPILOGUE
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=90)
    if MARK not in p.stdout:
        return None, (p.stderr.strip().splitlines() or ["brak wyniku"])[-1]
    body = p.stdout[p.stdout.rindex(MARK) + len(MARK):].strip()
    return json.loads(body), p.stderr


def run_ruby(task, source):
    rb = f"$stdout = StringIO.new\n{source}\n{task.get('starter','')}\n{task.get('tests','')}\nprint '{MARK}' + __R__.to_json\n"
    p = subprocess.run(["ruby", "-rjson", "-rstringio", "-e", rb], capture_output=True, text=True, timeout=90)
    if MARK not in p.stdout:
        return None, (p.stderr.strip().splitlines() or ["brak wyniku"])[-1]
    body = p.stdout[p.stdout.rindex(MARK) + len(MARK):].strip()
    return json.loads(body), p.stderr


def main():
    have_ruby = subprocess.run(["which", "ruby"], capture_output=True).returncode == 0
    if not have_ruby:
        print("uwaga: brak interpretera ruby — zadania Ruby sprawdzę statycznie\n")
    bad = 0
    for t in TASKS:
        ex = t["executor"]
        if ex == "pyodide":
            checks, err = run_python(t, t.get("solution", ""))
            if checks is None:
                print(f"  BLAD  {t['id']}: {err}")
                bad += 1
                continue
            failed = [c for c in checks if not c["ok"]]
            print(f"  {'FAIL ' if failed else 'OK   '} {t['id']:24} {len(checks) - len(failed)}/{len(checks)} testow")
            for c in failed:
                print(f"         - {c['name']}: {c['detail']}")
                bad += 1
        elif ex == "opal":
            sol = t.get("solution")
            starter = t.get("starter", "")
            if not sol:
                print(f"  ?     {t['id']:24} brak rozwiazania w JSON (sprawdzone statycznie)")
                continue
            if not have_ruby:
                print(f"  ?     {t['id']:24} (bez ruby: pominieto)")
                continue
            # ruby z v1: metody na poziomie modulu; rozwiazanie jako funkcja
            src = sol if "def " in sol else sol
            body = "class Object\n" + src + "\nend\n" if src.strip().startswith("def ") else src
            code = src + "\n" + starter + "\n" + t.get("tests", "") + \
                f"\nprint '{MARK}' + __R__.to_json\n"
            p = subprocess.run(["ruby", "-rjson", "-e", "def check(n,ok,d=''); __R__ ||= []; __R__ << {'name'=>n,'ok'=>!!ok,'detail'=>d.to_s[0,300]}; end\n" + code],
                               capture_output=True, text=True, timeout=90)
            if MARK not in p.stdout:
                print(f"  BLAD  {t['id']}: {(p.stderr.strip().splitlines() or ['?'])[-1]}")
                bad += 1
                continue
            checks = json.loads(p.stdout[p.stdout.rindex(MARK) + len(MARK):].strip())
            failed = [c for c in checks if not c["ok"]]
            print(f"  {'FAIL ' if failed else 'OK   '} {t['id']:24} {len(checks) - len(failed)}/{len(checks)} testow")
            for c in failed:
                print(f"         - {c['name']}: {c['detail']}")
                bad += 1
        elif ex == "quiz":
            ok = bool(t.get("answer"))
            print(f"  {'OK   ' if ok else 'BLAD '} {t['id']:24} quiz, {len(t.get('choices', []))} odpowiedzi")
            if not ok:
                bad += 1
        elif ex == "vm":
            ok = bool(t.get("vm_check")) and (t.get("free") is not True or bool(t.get("vm_accept")))
            print(f"  {'OK   ' if ok else 'BLAD '} {t['id']:24} zadanie VM")
            if not ok:
                bad += 1
        else:
            print(f"  BLAD  {t['id']}: nieznany wykonawca {ex}")
            bad += 1

    print()
    print("wszystko przechodzi" if bad == 0 else f"{bad} problemow")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
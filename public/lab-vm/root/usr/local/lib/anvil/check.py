#!/usr/bin/env python3
"""
check.py — klucz odpowiedzi dla labow, ktore oddaja plik JSON.

Kazde zadanie dostaje jeden `verify_*` ponizej. Weryfikujemy **wynik**, nie
sposob jego osiagniecia: rozwiazanie moze byc napisane w Pythonie, Rubym,
Bashu, czymkolwiek. Nic nie wychodzi z maszyny.

Oczekiwane wartosci pochodza z fixtures w ./fixtures (pliki expected-*.json
trzymaja klucz, wiec odpowiedz studenta moze nazywac sie tak samo jak
fixture) oraz ze stanu maszyny. Zmienisz fixture — zmieni sie i klucz.
"""
import json
import os
import pathlib
import sys

STUDENT = pathlib.Path(os.environ.get("ANVIL_LAB_ROOT", "/home/student"))
FIX = STUDENT / "fixtures"
PROBLEMS = []


def fail(msg):
    PROBLEMS.append(msg)


def load(name):
    """Plik rozwiazania studenta. Zwraca None i zglasza problem."""
    try:
        return json.loads((STUDENT / name).read_text())
    except FileNotFoundError:
        fail(f"brak pliku /home/student/{name}")
    except Exception as e:
        fail(f"/home/student/{name} nie jest poprawnym JSON-em: {e}")
    return None


def expected(name):
    return json.loads((FIX / f"expected-{name}.json").read_text())


def fixture(name):
    return json.loads((FIX / name).read_text())


# ---------------------------------------------------------------- scope-scan
def verify_scope_scan():
    """Raport ze skanu ma byc w zakresie, posortowany i miescic sie w budzecie."""
    targets = [l.strip() for l in (STUDENT / "targets.txt").read_text().splitlines()
               if l.strip() and not l.startswith("#")]
    budget = int((STUDENT / "budget").read_text().strip())
    answers = fixture("responses.json")
    report = load("scan.json")
    if report is None:
        return
    if not isinstance(report, list):
        fail("scan.json musi byc lista obiektow")
        return
    if not all(isinstance(e, dict) for e in report):
        fail("kazdy wpis musi byc obiektem z polem host")
        return

    hosts = [e.get("host") for e in report]
    if len(report) > budget:
        fail(f"raport ma {len(report)} wpisow, a budzet to {budget} — skaner wyszedl z zakresu")
    if len(set(hosts)) != len(hosts):
        fail("jaden host nie moze wystapic dwa razy — to ponowne odpytywanie")
    out = [h for h in hosts if h not in targets]
    if out:
        fail(f"poza zakresem: {', '.join(map(str, out))} — takie hosty konca zgloszeniem")
    missing = [h for h in targets if h not in hosts]
    if missing:
        fail(f"pominieto hosty z targets.txt: {', '.join(missing)}")
    if hosts != sorted(hosts):
        fail("raport musi byc posortowany po nazwie hosta")
    for e in report:
        want = answers.get(e.get("host"), {}).get("status")
        if e.get("status") != want:
            fail(f"status dla {e.get('host')!r} to {e.get('status')!r}, a w fixtures jest {want!r}")


# -------------------------------------------------------------- process-tree
def verify_process_tree():
    """Kto slucha na porcie, jako ktory uzytkownik, i skad to przyszlo."""
    truth = fixture("process-tree.json")
    got = load("proc.json")
    if got is None:
        return
    for key, label in (("command", "nazwa procesu"), ("user", "uzytkownik"),
                       ("started_by", "zrodlo (unit / skrypt / sesja)")):
        val = str(got.get(key, "")).strip()
        if not val:
            fail(f"brak pola {key} ({label})")
        elif not val.endswith(truth[key]):
            fail(f"{label}: piszesz {val!r}, a na maszynie jest {truth[key]!r}")


# -------------------------------------------------------------- capabilities
def verify_capabilities():
    """setuid: czyj to binary i co realnie zyskuje."""
    truth = expected("suid")
    got = load("suid.json")
    if got is None:
        return
    if str(got.get("owner_uid")) != str(truth["owner_uid"]):
        fail(f"owner_uid: {got.get('owner_uid')!r}, a setuid jest ustawione na {truth['owner_uid']}")
    body = json.dumps(got).lower()
    if not any(w in body for w in ("root", "euid", "effective")):
        fail("wyjasnij, ze setuid daje efektywne uprawnienia wlasciciela (euid), "
             "a nie uprawnienia z trybu zwyklego pliku")
    if not str(got.get("path", "")).strip():
        fail("podaj sciezke do binarki z bitami setuid")


# --------------------------------------------------------------- mount-audit
def verify_mount_audit():
    """Katalog stanu jest zapisywalny przez kazdego — i to jest problem."""
    truth = fixture("mount-audit.json")
    got = load("mounts.json")
    if got is None:
        return
    body = json.dumps(got)
    for path in truth["world_writable"]:
        if path not in body:
            fail(f"pominieto {path} — katalog stanu uslugi zapisywalny przez kazdego")
    for unit in truth["services"]:
        if unit not in body:
            fail(f"nie nazwales uslugi, ktora korzysta z tego katalogu ({unit})")


# ---------------------------------------------------------- cron-persistence
def verify_cron_persistence():
    """Mechanizm, ktory wskrzesza usunieta rzecz."""
    truth = fixture("persistence.json")
    got = load("persist.json")
    if got is None:
        return
    body = json.dumps(got)
    if truth["path"] not in body:
        fail(f"plik, ktory przywraca usuniete, to {truth['path']}")
    if not any(k in body for k in truth["any_of"]):
        fail("podaj linie, ktora to robi — wystarczy fragment, np. komenda z crontaba")


# ----------------------------------------------------------------- tcp-flags
def verify_tcp_flags():
    """Syn flood a kolejka; odpowiedz ma byc o loscie, nie o sloganie."""
    got = load("tcp.json")
    if got is None:
        return
    body = json.dumps(got).lower()
    for word in ("backlog", "syn_backlog", "syncookies"):
        if word not in body:
            fail(f"brak slowa kluczowego: {word} — bez niego opis nie odpowiada na pytanie")
    if not any(w in body for w in ("queue", "kolejk", "half-open", "polotworz")):
        fail("wyjasnij, co SYN robi z kolejka polaczen polotworych")


# --------------------------------------------------------------- cert-inspect
def verify_cert_inspect():
    """Certyfikat: subject, not-after i czy pokrywa nazwe, pod ktora weszliśmy."""
    truth = expected("cert")
    got = load("cert.json")
    if got is None:
        return
    if truth["subject"] not in str(got.get("subject", "")):
        fail(f"subject: {got.get('subject')!r}, a w certyfikacie jest {truth['subject']!r}")
    if not str(got.get("not_after", "")).startswith(truth["not_after"][:4]):
        fail(f"not_after: {got.get('not_after')!r}, a certyfikat wazny jest do {truth['not_after']!r}")
    if "hostname" not in json.dumps(got).lower() and "host" not in json.dumps(got).lower():
        fail("dodaj pole z ocena, czy certyfikat pokrywa nazwe, pod ktora go sprawdzales")


# ---------------------------------------------------------------- port-sweep
def verify_port_sweep():
    """Skan wlasnej maszyny, posortowany, w zakresie zadania."""
    got = load("ports.json")
    if got is None:
        return
    if not isinstance(got, list) or not all(isinstance(p, int) and not isinstance(p, bool) for p in got):
        fail("ports.json musi byc lista liczb calkowitych")
        return
    if got != sorted(got):
        fail("porty musza byc posortowane rosnaco")
    if len(set(got)) != len(got):
        fail("porty nie moga sie powtarzac")
    if not got:
        fail("lista pusta — na maszynie cos nasluchuje")
    out = [p for p in got if p < 1024 or p > 9000]
    if out:
        fail(f"poza zakresem zadania (1024-9000): {out}")
    missing = [p for p in fixture("open-ports.json") if p not in got]
    if missing:
        fail(f"pominieto otwarte porty: {missing}")


# ----------------------------------------------------------------- log-rotate
def verify_log_rotate():
    """Log jest pusty, bo rotation go wyczyscila."""
    truth = expected("rotate")
    got = load("rotate.json")
    if got is None:
        return
    if "logrotate" not in json.dumps(got):
        fail("sciezka konfiguracyjna powinna wskazywac na plik logrotate")
    if str(got.get("retention")) != str(truth["retention"]):
        fail(f"retention: {got.get('retention')!r}, a w konfiguracji jest {truth['retention']}")


# --------------------------------------------------------------- shell-history
def verify_shell_history():
    """Trzy komendy, ktore dotkaly sekretow."""
    got = load("history.json")
    if got is None:
        return
    cmds = got if isinstance(got, list) else got.get("commands", [])
    if not isinstance(cmds, list) or len(cmds) != 3:
        fail("history.json musi wymienic dokladnie trzy komendy (lista albo pole commands)")
        return
    # sekret wyciekl, gdy trafil do naglowka, do /tmp i poza maszyne
    for key in ("curl", "cp", "scp"):
        if not any(key in c for c in cmds):
            fail(f"pominieto komende z '{key}' — to ona dotkala sekretu")


# ------------------------------------------------------------ file-timestamps
def verify_file_timestamps():
    """mtime i ctime mowia wiecej niz tresc pliku."""
    truth = expected("timeline")
    got = load("timeline.json")
    if got is None:
        return
    for key in ("mtime", "ctime"):
        val = str(got.get(key, "")).strip()
        if not val:
            fail(f"brak pola {key}")
        elif val[:10] != truth[key][:10]:
            fail(f"{key}: {val!r}, a stat mowi {truth[key]!r}")


# ------------------------------------------------------------------ dns-trace
def verify_dns_trace():
    """Nazwa wskazuje na adres i na typ rekordu."""
    truth = expected("dns")
    got = load("dns.json")
    if got is None:
        return
    if str(got.get("address")) != truth["address"]:
        fail(f"address: {got.get('address')!r}, a /etc/hosts podaje {truth['address']}")
    if str(got.get("type", "")).lower() not in ("hosts", "a", "static", "/etc/hosts"):
        fail(f"typ rekordu: {got.get('type')!r} — ta nazwa rozwiazuje sie przez /etc/hosts, nie przez DNS")


# -------------------------------------------------------------- firewall-rule
def verify_firewall_rule():
    """Ktory port jest wystawiony na swiat i na ktorym interfejsie."""
    truth = expected("firewall")
    got = load("firewall.json")
    if got is None:
        return
    if str(got.get("port")) != str(truth["port"]):
        fail(f"port: {got.get('port')!r}, a regula zezwala na {truth['port']}")
    if str(got.get("interface", "")).lower() != truth["interface"].lower():
        fail(f"interface: {got.get('interface')!r}, a regula dotyczy {truth['interface']}")


CHECKS = {
    "scope-scan": verify_scope_scan,
    "process-tree": verify_process_tree,
    "capabilities": verify_capabilities,
    "mount-audit": verify_mount_audit,
    "cron-persistence": verify_cron_persistence,
    "tcp-flags": verify_tcp_flags,
    "cert-inspect": verify_cert_inspect,
    "port-sweep": verify_port_sweep,
    "log-rotate": verify_log_rotate,
    "shell-history": verify_shell_history,
    "file-timestamps": verify_file_timestamps,
    "dns-trace": verify_dns_trace,
    "firewall-rule": verify_firewall_rule,
}


def main():
    task = sys.argv[1] if len(sys.argv) > 1 else ""
    verify = CHECKS.get(task)
    if not verify:
        print(f"FAIL  brak weryfikatora dla {task!r}")
        return 2
    try:
        verify()
    except FileNotFoundError as e:
        print(f"FAIL  brak pliku fixtures: {e}")
        return 1
    except Exception as e:  # zly format rozwiazania to nie wyjatkiem labu
        print(f"FAIL  {task}: {e}")
        return 1
    if PROBLEMS:
        for p in PROBLEMS:
            print(f"FAIL  {task}: {p}")
        return 1
    print(f"OK  {task}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

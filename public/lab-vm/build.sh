#!/usr/bin/env bash
# lab-vm/build.sh — buduje maszyne wirtualna dla labow Anvila.
#
# Maszyna to qcow2 z minimalnym userlandem (python3, ruby, rust), celowo
# podatna usluga oraz `labcheck`, ktory weryfikuje rozwiazania bez sieci.
#
#   bash lab-vm/build.sh           # zbuduj obraz w lab-vm/anvil-lab.qcow2
#   bash lab-vm/build.sh --run     # zbuduj i odpal w QEMU
#   bash lab-vm/build.sh --host    # tylko przygotuj katalog, do testow
#   bash lab-vm/build.sh --test    # odpal wszystkie weryfikatory na sucho
#
# Wymagania do pelnego obrazu: qemu-system-x86_64, qemu-img, genisoimage|xorriso.
# Bez nich --host konfiguruje usluwe lokalnie (wystarczy do testow).
#
# root/ jest ZRODLEM PRAWDY: to co tam lezi, trafia do obrazu. build.sh
# niczego nie generuje w sciezce — inaczej root i obraz rozjezdza sie
# po kilku miesiacach, a polowa laboratoriow przestaje miec weryfikator.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$HERE/root"
NAME="anvil-lab"
IMG="$HERE/$NAME.qcow2"
SIZE="${ANVIL_VM_SIZE:-4G}"
MEM="${ANVIL_VM_MEM:-2048}"
PORT_SSH="${ANVIL_VM_SSH:-2222}"
RUN_MODE=0
HOST_ONLY=0
TEST_ONLY=0
STAGE=""

for a in "$@"; do
  case "$a" in
    --run) RUN_MODE=1 ;;
    --host) HOST_ONLY=1 ;;
    --test) TEST_ONLY=1 ;;
  esac
done

log() { printf '\033[2m[lab-vm]\033[0m %s\n' "$1"; }
die() { printf '\033[31m[lab-vm] %s\033[0m\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "brak $1 — zainstaluj albo uzyj --host"; }
cleanup() { [ -n "$STAGE" ] && [ -d "$STAGE" ] && rm -rf "$STAGE"; }
trap cleanup EXIT

# ------------------------------------------------------------------ stage
# Kopiujemy root/ do katalogu roboczego i poprawiamy uprawnienia — same
# pliki w repo zostaja nietkniete.
stage() {
  [ -d "$ROOT" ] || die "brak katalogu $ROOT"
  STAGE="$(mktemp -d "${TMPDIR:-/tmp}/anvil-root.XXXXXX")"
  cp -a "$ROOT/." "$STAGE/"
  chmod +x "$STAGE/bin/labcheck" "$STAGE/bin/busybox" \
            "$STAGE/usr/local/bin/anvil-lab" "$STAGE/usr/local/bin/anvil-setuid" \
            "$STAGE/opt/anvil/anvil-lab" "$STAGE/usr/local/lib/anvil/check.py" 2>/dev/null || true
  # Podatnosci, o ktore pytaja laby, musza byc odtwarzalne po rozpakowaniu.
  chmod 4755 "$STAGE/usr/local/bin/anvil-setuid" 2>/dev/null || true
  chmod 0644 "$STAGE/home/student/.anvil/id_ed25519" 2>/dev/null || true
  chmod 0777 "$STAGE/var/lib/anvil-lab/state" 2>/dev/null || true
  mkdir -p "$STAGE"/{proc,sys,dev,tmp,run}
  log "stage gotowy: $STAGE"
}

# ------------------------------------------------------------------- test
# Odpala kazdy weryfikator na dwoch rozwiazaniach: jednym poprawnym
# i jednym celowo zlym. Weryfikator, ktory przepuszcza zly, jest
# bezuzyteczny — i taki wlasnie bug najczesciej przepada.
install_reference_solutions() {
  local s="$STAGE/home/student"
  ANVIL_LOG="$STAGE/var/log/anvil-lab.log" \
    python3 - "$STAGE" <<'PY'
import json, pathlib, sys

stage = pathlib.Path(sys.argv[1])
s = stage / "home/student"
fix = s / "fixtures"

def w(name, data):
    (s / name).write_text(json.dumps(data, indent=2) + "\n")

def ex(name):
    return json.loads((fix / f"expected-{name}.json").read_text())

def fx(name):
    return json.loads((fix / name).read_text())

targets = [l.strip() for l in (s / "targets.txt").read_text().splitlines()
           if l.strip() and not l.startswith("#")]
w("scan.json", [{"host": h, "status": fx("responses.json")[h]["status"]}
                for h in sorted(targets)])
w("proc.json", fx("process-tree.json"))

suid = ex("suid")
w("suid.json", {"path": suid["path"], "owner_uid": suid["owner_uid"],
                "privilege": "setuid: effective uid follows the file owner, so this runs as root"})

ma = fx("mount-audit.json")
w("mounts.json", {"world_writable": ma["world_writable"], "services": ma["services"]})

per = fx("persistence.json")
w("persist.json", {"path": per["path"], "line": per["any_of"][0] + " ..."})

w("tcp.json", {"syn_flood": "fills the accept backlog with half-open connections",
               "backlog": "tcp_max_syn_backlog",
               "mitigation": "net.ipv4.tcp_syncookies issues a cookie instead of state"})

cert = ex("cert")
w("cert.json", {"subject": cert["subject"], "not_after": cert["not_after"],
                "hostname": cert["hostname"], "covers_hostname": True})

w("ports.json", sorted(fx("open-ports.json")))
w("history.json", {"commands": ["curl -H 'X-Api-Key: anvil-live-key-4711' ...",
                                "cp ~/.anvil/id_ed25519 /tmp/x",
                                "scp ~/.anvil/id_ed25519 backup@drop.internal:~/k"]})
(s / "key.json").write_text(json.dumps(
    {"path": "/home/student/.anvil/id_ed25519", "before": "644", "after": "600"},
    indent=2) + "\n")

# klucz odpowiedzi kopiujemy wprost — plik expected-X.json jest jednoczesnie
# tym, co student musi napisac, wiec zawiera juz dokladnie oczekiwany JSON.
for name in ("rotate", "timeline", "dns", "firewall"):
    (s / f"{name}.json").write_text((fix / f"expected-{name}.json").read_text())

# celowo zle odpowiedzi — dla kontroli, ze weryfikator cos odrzuca
(s / ".anvil").mkdir(exist_ok=True)
(s / ".anvil/scan.bad.json").write_text(json.dumps(
    [{"host": targets[0], "status": 200},
     {"host": "lab-d.internal", "status": 200},
     {"host": targets[0], "status": 200}]))
(s / ".anvil/suid.bad.json").write_text(json.dumps(
    {"path": suid["path"], "owner_uid": 1000}))
(s / ".anvil/cert.bad.json").write_text(json.dumps(
    {"subject": "CN=wrong", "not_after": "2020-01-01", "hostname": "other.internal"}))
(s / ".anvil/ports.bad.json").write_text(json.dumps(sorted(fx("open-ports.json"))[:-1]))
(s / ".anvil/rotate.bad.json").write_text(json.dumps(
    {"config": "/etc/logrotate.d/anvil-lab", "retention": 99}))
PY

  # ruby
  cat > "$s/events.rb" <<'RB'
E = [{'id' => 4, 'severity' => 'low',  'type' => 'file_open'},
     {'id' => 9, 'severity' => 'high', 'type' => 'exec'},
     {'id' => 2, 'severity' => 'high', 'type' => 'file_open'},
     {'id' => 7, 'severity' => 'low',  'type' => 'auth'},
     {'id' => 1, 'severity' => 'low',  'type' => 'exec'}]
CALM = [{'id' => 4, 'severity' => 'low', 'type' => 'file_open'},
        {'id' => 7, 'severity' => 'low', 'type' => 'auth'}]
def suspicious(events)
  events.select { |e| e['severity'] == 'high' || e['type'] == 'exec' }.map { |e| e['id'] }.sort
end
def counts_by(events, key)
  events.each_with_object(Hash.new(0)) { |e, h| h[e[key]] += 1 }
end
def flat(h) = h.keys.sort.map { |k| "#{k}:#{h[k]}" }.join(',')

puts "suspicious=#{suspicious(E).join(',')}"
puts "calm=#{suspicious(CALM).join(',')}"
puts "counts_by_severity=#{flat(counts_by(E, 'severity'))}"
RB
  cat > "$s/redact.rb" <<'RB'
def redact(text)
  count = 0
  out = text.gsub(/\b(?:\d{4}[ -]){3}\d{4}\b/) { |m| count += 1; '****-****-****-' + m[-4, 4] }
  [out, count]
end
RB
  # rust: poprawiona wersja programu z bledem wypozyczenia
  cat > "$s/main.rs" <<'RS'
fn main() {
    let mut v = vec![1, 2, 3];
    let first = v[0];
    v.push(4);
    println!("{:?} {}", v, first);
}
RS
  cat > "$s/src/lib.rs" <<'RS'
pub fn longest<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.len() >= b.len() { a } else { b }
}
RS
  chmod 600 "$s/.anvil/id_ed25519"
  # Uruchamiamy usluge raz z debug=true, zeby log naprawde zawieral wyciek.
  ANVIL_DEBUG=true ANVIL_LOG="$STAGE/var/log/anvil-lab.log" \
    python3 "$STAGE/usr/local/bin/anvil-lab" probe >/dev/null 2>&1 || true
  local tok
  tok=$(sed -n 's/.*ANVIL_DEBUG_TOKEN=\([^ ]*\).*/\1/p' "$STAGE/var/log/anvil-lab.log" | head -1)
  printf '{\n  "token": "%s",\n  "flag": "%s",\n  "note": "not pasted into a chat"\n}\n' \
    "$tok" "$tok" > "$s/leak.json"
}

# Probuje zadanie z poprawnym rozwiazaniem, a potem z celowo zlym.
test_labs() {
  stage
  install_reference_solutions
  local root="$STAGE"
  local s="$STAGE/home/student"
  local pass=0 fail=0 bad=0
  for t in leak-report scope-scan sec-l1-webscan process-tree capabilities mount-audit \
           cron-persistence tcp-flags cert-inspect port-sweep log-rotate shell-history \
           file-timestamps dns-trace firewall-rule ffi-wrapper ruby-enumerable ruby-redact \
           rust-borrow rust-lifetime key-permissions; do
    local out
    out=$(ANVIL_LAB_ROOT="$s" ANVIL_LOG="$root/var/log/anvil-lab.log" \
           "$root/bin/labcheck" --task "$t" 2>&1) || true
    if printf '%s' "$out" | grep -q '^OK'; then
      printf '  \033[32mOK\033[0m    %s\n' "$t"
      pass=$((pass + 1))
    else
      printf '  \033[31mFAIL\033[0m  %s\n' "$t"
      printf '%s\n' "$out" | sed 's/^/        /'
      fail=$((fail + 1))
    fi
  done

  # Teraz to samo, ale z rozwiazaniem celowo blednym. Weryfikator, ktore
  # przepuszcza zla odpowiedz, daje uczniowi zly sygnal.
  printf '\n  kontrola: weryfikatory musza odrzucac zle rozwiazania\n'
  cp "$s/scan.json" "$s/.anvil/scan.json.good"; cp "$s/.anvil/scan.bad.json" "$s/scan.json"
  out=$(ANVIL_LAB_ROOT="$s" "$root/bin/labcheck" --task scope-scan 2>&1) || true
  if printf '%s' "$out" | grep -q '^OK'; then
    printf '  \033[31mZLY\033[0m  scope-scan przepuscil raport z hostem spoza zakresu\n'; bad=$((bad+1))
  else
    printf '  \033[32mOK\033[0m    scope-scan odrzucil raport spoza zakresu\n'
  fi
  mv "$s/.anvil/scan.json.good" "$s/scan.json"

  cp "$s/suid.json" "$s/.anvil/suid.json.good"; cp "$s/.anvil/suid.bad.json" "$s/suid.json"
  out=$(ANVIL_LAB_ROOT="$s" "$root/bin/labcheck" --task capabilities 2>&1) || true
  if printf '%s' "$out" | grep -q '^OK'; then
    printf '  \033[31mZLY\033[0m  capabilities przepuscil zly owner_uid\n'; bad=$((bad+1))
  else
    printf '  \033[32mOK\033[0m    capabilities odrzucil zly owner_uid\n'
  fi
  mv "$s/.anvil/suid.json.good" "$s/suid.json"

  cp "$s/cert.json" "$s/.anvil/cert.json.good"; cp "$s/.anvil/cert.bad.json" "$s/cert.json"
  out=$(ANVIL_LAB_ROOT="$s" "$root/bin/labcheck" --task cert-inspect 2>&1) || true
  if printf '%s' "$out" | grep -q '^OK'; then
    printf '  \033[31mZLY\033[0m  cert-inspect przepuscil zly subject\n'; bad=$((bad+1))
  else
    printf '  \033[32mOK\033[0m    cert-inspect odrzucil zly subject\n'
  fi
  mv "$s/.anvil/cert.json.good" "$s/cert.json"

  cp "$s/ports.json" "$s/.anvil/ports.json.good"; cp "$s/.anvil/ports.bad.json" "$s/ports.json"
  out=$(ANVIL_LAB_ROOT="$s" "$root/bin/labcheck" --task port-sweep 2>&1) || true
  if printf '%s' "$out" | grep -q '^OK'; then
    printf '  \033[31mZLY\033[0m  port-sweep przepuscil niepelna liste\n'; bad=$((bad+1))
  else
    printf '  \033[32mOK\033[0m    port-sweep odrzucil niepelna liste\n'
  fi
  mv "$s/.anvil/ports.json.good" "$s/ports.json"

  chmod 644 "$s/.anvil/id_ed25519"
  out=$(ANVIL_LAB_ROOT="$s" "$root/bin/labcheck" --task key-permissions 2>&1) || true
  if printf '%s' "$out" | grep -q '^OK'; then
    printf '  \033[31mZLY\033[0m  key-permissions przepuscil klucz na 644\n'; bad=$((bad+1))
  else
    printf '  \033[32mOK\033[0m    key-permissions odrzucil klucz na 644\n'
  fi
  chmod 600 "$s/.anvil/id_ed25519"

  printf '  zly snippet nadal nie kompiluje sie: '
  if rustc -o /dev/null "$s/main.rs" 2>/dev/null; then
    printf '\033[31mNIE\033[0m — proba labu nie jest proba\n'; bad=$((bad+1))
  else
    printf '\033[32mTAK\033[0m\n'
  fi

  printf '\n  %d z %d weryfikatorow dziala, %d przepuszcilo zla odpowiedz\n' \
    "$pass" "$((pass + fail))" "$bad"
  [ "$fail" -eq 0 ] && [ "$bad" -eq 0 ]
}

# ---------------------------------------------------------------- obraz ISO
build_iso() {
  stage
  local root="$STAGE"
  log "przygotowanie systemu plikow ($root)"

  cat > "$root/etc/motd" <<'EOF'
Anvil Lab VM

  labcheck --task <id>     sprawdz swoje rozwiazanie
  python3 -V / ruby -v     interpretery
  /usr/local/bin/anvil-lab --version

  Zadania: https://edu.hartwell-labs.pl/lab
EOF

  if [ "$HOST_ONLY" = "1" ]; then
    log "--host: pominieto obraz, root jest w $root"
    log "odpal weryfikatory: ANVIL_LAB_ROOT=$root/home/student $root/bin/labcheck --task <id>"
    return 0
  fi

  need qemu-img
  need genisoimage || need xorriso || need mkisofs

  local isobin mkfs=""
  for c in genisoimage xorriso mkisofs; do
    if command -v "$c" >/dev/null 2>&1; then isobin="$c"; break; fi
  done
  [ -n "$isobin" ] || die "brak narzedzia do ISO (genisoimage|xorriso|mkisofs)"

  local isopath="$HERE/$NAME.iso"
  log "pakowanie ISO ($isobin)"
  if [ "$isobin" = "xorriso" ]; then
    xorriso -as mkisofs -o "$isopath" -r "$root" >/dev/null 2>&1
  else
    "$isobin" -o "$isopath" -r "$root" >/dev/null 2>&1
  fi

  log "tworzenie qcow2 ($SIZE)"
  qemu-img create -f qcow2 "$IMG" "$SIZE" >/dev/null
  cat > /tmp/anvil-drive.sh <<DRIVE
set -e
DRIVE
  qemu-img dd if="$isopath" of="$IMG" bs=4M 2>/dev/null || {
    # qemu-img dd bywa wyłączone w nowszych wersjach — dołączamy obraz jako napęd
    log "qemu-img dd niedostepne, obraz ISO zostal obok: $isopath"
  }
  log "gotowe: $IMG"
}

# ------------------------------------------------------------------- run
run_vm() {
  need qemu-system-x86_64
  build_iso
  log "odpalam QEMU (port SSH $PORT_SSH)"
  exec qemu-system-x86_64 \
    -m "$MEM" -smp 2 \
    -drive "file=$IMG,format=qcow2,if=virtio" \
    -netdev user,id=n0,hostfwd=tcp::$PORT_SSH-:22 \
    -device virtio-net-pci,netdev=n0 \
    -nographic
}

case "$TEST_ONLY$HOST_ONLY" in
  10) test_labs ;;
  01) build_iso ;;
  11) test_labs; build_iso ;;
  *)  if [ "$RUN_MODE" = "1" ]; then run_vm; else build_iso; fi ;;
esac

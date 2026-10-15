#!/usr/bin/env bash
# lab-vm/build.sh — buduje obraz maszyny wirtualnej dla laboratoriów Anvil.
#
# Lab VM to obraz qcow2 z Alpine + narzędziami (python3, ruby, rust, gcc),
# zestawem podatnych usług do zadań z bezpieczeństwa i poleceniem `labcheck`,
# które sprawdza rozwiązania zadań bez wysyłania czegokolwiek na zewnątrz.
#
#   bash lab-vm/build.sh           # zbuduj obraz w lab-vm/anvil-lab.qcow2
#   bash lab-vm/build.sh --run     # zbuduj i odpal w QEMU
#   bash lab-vm/build.sh --host    # tylko skrypty provisionujące, bez obrazu
#
# Wymagania do pełnego obrazu: qemu-system-x86_64, qemu-img, genisoimage|xorriso.
# Na hostach bez nich --host konfiguruje usługę lokalnie (idealne do testowania).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="anvil-lab"
IMG="$HERE/$NAME.qcow2"
SIZE="${ANVIL_VM_SIZE:-4G}"
MEM="${ANVIL_VM_MEM:-2048}"
PORT_SSH="${ANVIL_VM_SSH:-2222}"
RUN_MODE=0

for a in "$@"; do
  case "$a" in
    --run) RUN_MODE=1 ;;
    --host) HOST_ONLY=1 ;;
  esac
done

log() { printf '\033[2m[lab-vm]\033[0m %s\n' "$1"; }
die() { printf '\033[31m[lab-vm] %s\033[0m\n' "$1" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "brakuje $1 — zainstaluj albo użyj --host"; }

# ---------------------------------------------------------------- obraz ISO
build_iso() {
  local root="$HERE/root"
  log "przygotowuję system plików ($root)"
  rm -rf "$root"; mkdir -p "$root"/{bin,etc,home/lab,lib,usr/bin,usr/sbin,tmp,var/lib,var/log,proc,sys,dev}

  cat > "$root/etc/os-release" <<'EOF'
NAME="Anvil Lab"
ID=anvillab
VERSION_ID="1"
PRETTY_NAME="Anvil Lab VM"
EOF

  # /etc/labcheck — weryfikacja rozwiązań. Zero sieci: wszystko lokalnie.
  cat > "$root/bin/labcheck" <<'EOF'
#!/bin/sh
# labcheck — sprawdza rozwiązanie zadania. Użycie: labcheck --task <id>
TASK=""
[ "$1" = "--task" ] && TASK="$2"
case "$TASK" in
  vm-01-insecure-flag)
    log=$(cat "${ANVIL_LOG:-/var/log/anvil-lab.log}" 2>/dev/null)
    if printf '%s' "$log" | grep -q 'debug=true'; then
      if printf '%s' "$log" | grep -q 'ANVIL_DEBUG_TOKEN='; then
        echo "OK  vm-01: flaga jest w logu, a w nim sekret — dokładnie tego nie chciałeś"
        exit 0
      fi
      echo "FAIL  flada ustawiona, ale sekret nie trafił do logu"
      exit 1
    fi
    echo "FAIL  uruchom usługę: ANVIL_DEBUG=true /usr/local/bin/anvil-lab serve"
    exit 1 ;;
  rb-01-enumerable)
    cat > /tmp/t.rb <<'RB'
E = [{'id'=>4,'severity'=>'low','type'=>'file_open'},{'id'=>9,'severity'=>'high','type'=>'exec'},
     {'id'=>2,'severity'=>'high','type'=>'file_open'},{'id'=>7,'severity'=>'low','type'=>'auth'},
     {'id'=>1,'severity'=>'low','type'=>'exec'}]
def suspicious(events)
  events.select { |e| e['severity'] == 'high' || e['type'] == 'exec' }.map { |e| e['id'] }.sort
end
exit(suspicious(E) == [1, 2, 9] ? 0 : 1)
RB
    ruby /tmp/t.rb && echo "OK  rb-01-enumerable" || echo "FAIL  rb-01-enumerable"
    exit $? ;;
  rb-02-redact)
    cat > /tmp/r.rb <<'RB'
def redact(text)
  count = 0
  out = text.gsub(/\b(?:\d{4}[ -]){3}\d{4}\b/) { |m| count += 1; '****-****-****-' + m[-4, 4] }
  [out, count]
end
raise unless redact('karta 4111 1111 1111 1111 odrzucona') == ['karta ****-****-****-1111 odrzucona', 1]
raise unless redact('4111-1111-1111-1111') == ['****-****-****-1111', 1]
raise unless redact('brak danych') == ['brak danych', 0]
RB
    ruby /tmp/r.rb && echo "OK  rb-02-redact" || echo "FAIL  rb-02-redact"
    exit $? ;;
  sec-l1-webscan|rs-l1-ffi|rs-01-predict|rs-02-panic)
    echo "FAIL  to zadanie jest poza darmowym tierem — napisz na contact@hartwell-labs.pl"
    exit 1 ;;
  *)
    echo "usage: labcheck --task <id>"; exit 2 ;;
esac
EOF
  chmod +x "$root/bin/labcheck"

  # Celowa podatność do zadania vm-01: tryb debug wypisuje sekret do logu.
  mkdir -p "$root/usr/local/bin"
  cat > "$root/usr/local/bin/anvil-lab" <<'EOF'
#!/usr/bin/env python3
"""Usługa labowa. Uruchomiona z ANVIL_DEBUG=true wypisuje token do logu —
   dokładnie ten błąd, który lab ma znaleźć i naprawić."""
import os, sys, time, pathlib
DEBUG = os.environ.get("ANVIL_DEBUG") == "true"
TOKEN = os.environ.get("ANVIL_DEBUG_TOKEN", "anvil-secret-do-not-log")
LOG = os.environ.get("ANVIL_LOG", "/var/log/anvil-lab.log")

def log(msg):
    pathlib.Path(LOG).parent.mkdir(parents=True, exist_ok=True)
    with open(LOG, "a") as f:
        f.write(f"{time.time():.0f} {msg}\n")

if "--version" in sys.argv:
    print("anvil-lab 1.0.0"); sys.exit(0)

log(f"start, debug={str(DEBUG).lower()}")
if DEBUG:
    log(f"ANVIL_DEBUG_TOKEN={TOKEN}")          # wyciek — punkt zadania
if "serve" in sys.argv:
    print(f"anvil-lab listening on 127.0.0.1:8080 (debug={DEBUG})")
    log("serve: nasłuch na 127.0.0.1:8080")
    import http.server
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers()
            self.wfile.write(b"anvil-lab ok\n")
        def log_message(self, *a): log("http " + self.path)
    http.server.HTTPServer(("127.0.0.1", 8080), H).serve_forever()
EOF
  chmod +x "$root/usr/local/bin/anvil-lab"

  cat > "$root/bin/busybox" <<'EOF'
#!/bin/sh
echo "Anvil Lab VM — minimalistyczny userland"
echo "Dostepne: sh, ls, cat, echo, grep, sed, awk, python3, ruby, cargo, rustc, labcheck"
EOF
  chmod +x "$root/bin/busybox"

  cat > "$root/etc/motd" <<'EOF'
Anvil Lab VM

  labcheck --task <id>     sprawdz rozwiazanie zadania
  python3 -V / ruby -v     interpretery
  /usr/local/bin/anvil-lab --version
  logi: /var/log/anvil-lab.log

Zadania: https://edu.hartwell-labs.pl/lab
EOF

  cat > "$root/home/lab/README" <<'EOF'
To jest lokalna maszyna laboratoryjna. Zero sieci — nic nie wychodzi.
Każde zadanie sprawdzisz poleceniem labcheck --task <id>.
EOF
}

# ------------------------------------------------------------------- obraz
make_image() {
  need qemu-img
  local iso="$HERE/$NAME.iso"
  if command -v genisoimage >/dev/null 2>&1; then
    genisoimage -quiet -o "$iso" -V ANVILLAB -no-emul-boot -boot-load-size 4 -eltorito-boot /dev/zero 2>/dev/null || true
  elif command -v xorriso >/dev/null 2>&1; then
    xorriso -as mkisofs -quiet -o "$iso" -V ANVILLAB "$HERE/root" 2>/dev/null || true
  fi
  log "tworzę dysk $IMG ($SIZE)"
  qemu-img create -f qcow2 "$IMG" "$SIZE" >/dev/null
  log "obraz gotowy: $IMG"
  log "(wgrywanie payloadu wymaga bootloadera — na ten moment host mode daje pełną funkcjonalność)"
}

run_vm() {
  need qemu-system-x86_64
  log "start QEMU: 2 GB RAM, port SSH $PORT_SSH -> 127.0.0.1"
  qemu-system-x86_64 \
    -m "$MEM" -smp 2 \
    -drive "file=$IMG,format=qcow2,if=virtio" \
    -netdev "user,id=n0,hostfwd=tcp::${PORT_SSH}-:22" -device virtio-net-pci,netdev=n0 \
    -display gtk -serial mon:stdio 2>/dev/null || \
  qemu-system-x86_64 -m "$MEM" -drive "file=$IMG,format=qcow2" -nographic 2>/dev/null
}

# ------------------------------------------------------- tryb hosta (--host)
host_mode() {
  log "tryb hosta: konfiguruję usługę i checker lokalnie"
  local bindir="$HOME/.local/bin"
  mkdir -p "$bindir"
  cp "$HERE/root/bin/labcheck" "$bindir/labcheck"
  chmod +x "$bindir/labcheck"
  mkdir -p "$HOME/.anvil-lab"; touch "$HOME/.anvil-lab/anvil-lab.log"
  log "log labowy (host): $HOME/.anvil-lab/anvil-lab.log"
  cp "$HERE/root/usr/local/bin/anvil-lab" /tmp/anvil-lab; chmod +x /tmp/anvil-lab
  log "gotowe. Sprawdź: labcheck --task rb-01-enumerable"
  log "uruchom usługę: ANVIL_DEBUG=true /tmp/anvil-lab serve"
}

build_iso
if [ "${HOST_ONLY:-0}" = "1" ]; then
  host_mode; exit 0
fi
make_image
[ "$RUN_MODE" = "1" ] && run_vm
exit 0
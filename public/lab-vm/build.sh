#!/usr/bin/env bash
# lab-vm/build.sh — builds the virtual machine image used by the Anvil labs.
#
# The lab VM is a qcow2 image with a minimal userland (python3, ruby, rust),
# a deliberately vulnerable service for the security labs, and `labcheck`, which
# verifies solutions without sending anything outside.
#
#   bash lab-vm/build.sh           # zbuduj obraz w lab-vm/anvil-lab.qcow2
#   bash lab-vm/build.sh --run     # zbuduj i odpal w QEMU
#   bash lab-vm/build.sh --host    # provisioning scripts only, no image
#
# Wymagania do pełnego obrazu: qemu-system-x86_64, qemu-img, genisoimage|xorriso.
# On hosts without those, --host configures the service locally (good enough for testing).
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

need() { command -v "$1" >/dev/null 2>&1 || die "missing $1 — install it or use --host"; }

# ---------------------------------------------------------------- obraz ISO
build_iso() {
  local root="$HERE/root"
  log "preparing the filesystem ($root)"
  rm -rf "$root"; mkdir -p "$root"/{bin,etc,home/lab,lib,usr/bin,usr/sbin,tmp,var/lib,var/log,proc,sys,dev}

  cat > "$root/etc/os-release" <<'EOF'
NAME="Anvil Lab"
ID=anvillab
VERSION_ID="1"
PRETTY_NAME="Anvil Lab VM"
EOF

  # /bin/labcheck — solution checker. No network: everything is local.
  cat > "$root/bin/labcheck" <<'EOF'
#!/bin/sh
# labcheck — checks your solution. Usage: labcheck --task <id>
TASK=""
[ "$1" = "--task" ] && TASK="$2"
case "$TASK" in
  vm-01-insecure-flag|vm-01)
    log=$(cat "${ANVIL_LOG:-/var/log/anvil-lab.log}" 2>/dev/null)
    if printf '%s' "$log" | grep -q 'debug=true'; then
      if printf '%s' "$log" | grep -q 'ANVIL_DEBUG_TOKEN='; then
        echo "OK  vm-01: the flag is in the log, and so is the secret — exactly what you did not want"
        exit 0
      fi
      echo "FAIL  the flag is set, but the secret never reached the log"
      exit 1
    fi
    echo "FAIL  start the service first: ANVIL_DEBUG=true /usr/local/bin/anvil-lab serve"
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
  sec-l1-webscan)
    # The lab asks for /home/student/scan.json: one entry per target, only in
    # scope, sorted, and never more requests than the budget allows.
    if [ ! -f /home/student/scan.json ]; then
      echo "FAIL  sec-l1-webscan: /home/student/scan.json not found — write the scanner first"
      exit 1
    fi
    python3 - <<'PY'
import json, pathlib, sys
scope = {l.strip() for l in pathlib.Path('/home/student/targets.txt').read_text().split() if l.strip()}
budget = int(pathlib.Path('/home/student/budget').read_text().strip())
try:
    data = json.loads(pathlib.Path('/home/student/scan.json').read_text())
except Exception as e:
    print(f"FAIL  sec-l1-webscan: scan.json is not valid JSON ({e})"); sys.exit(1)
if not isinstance(data, list) or not data:
    print("FAIL  sec-l1-webscan: expected a non-empty JSON list of results"); sys.exit(1)
hosts = [r.get('host') for r in data]
outside = [h for h in hosts if h not in scope]
if outside:
    print(f"FAIL  sec-l1-webscan: out of scope target(s): {', '.join(map(str, outside))}"); sys.exit(1)
if len(hosts) != len(set(hosts)):
    print("FAIL  sec-l1-webscan: duplicate hosts — scan each target once"); sys.exit(1)
if hosts != sorted(hosts):
    print("FAIL  sec-l1-webscan: results are not sorted by host, so runs cannot be diffed"); sys.exit(1)
if len(hosts) > budget:
    print(f"FAIL  sec-l1-webscan: {len(hosts)} requests, budget is {budget}"); sys.exit(1)
print(f"OK  sec-l1-webscan: {len(hosts)}/{budget} requests, in scope, sorted")
PY
    exit $? ;;
  rs-l1-ffi)
    # The lab asks for a crate that wraps bpf_probe_read_user safely: it has to
    # build, and its tests have to pass.
    if [ ! -d /home/student/ffi ]; then
      echo "FAIL  rs-l1-ffi: /home/student/ffi not found — put the crate there"
      exit 1
    fi
    if cargo build --quiet --manifest-path /home/student/ffi/Cargo.toml 2>/tmp/ffi-build.log; then
      if cargo test --quiet --manifest-path /home/student/ffi/Cargo.toml 2>/tmp/ffi-test.log; then
        echo "OK  rs-l1-ffi: builds clean and the tests pass"
        exit 0
      fi
      echo "FAIL  rs-l1-ffi: builds, but a test failed:"; tail -5 /tmp/ffi-test.log; exit 1
    fi
    echo "FAIL  rs-l1-ffi: does not compile:"; tail -8 /tmp/ffi-build.log; exit 1 ;;
  rs-01-predict|rs-02-panic)
    # Quizzes are checked in the browser; here you can compile the snippet and
    # read the compiler's own words.
    cat > /tmp/main.rs <<'RS'
fn main() {
    let s = String::from("anvil");
    let t = s;
    println!("{} {}", s, t);
}
RS
    mkdir -p /tmp/predict/src && cp /tmp/main.rs /tmp/predict/src/main.rs
    printf '[package]\nname = "predict"\nversion = "0.1.0"\nedition = "2021"\n' > /tmp/predict/Cargo.toml
    if cargo build --quiet --manifest-path /tmp/predict/Cargo.toml 2>/tmp/predict.log; then
      echo "OK  $TASK: compiled — re-read the question, the quiz decides"
    else
      echo "OK  $TASK: the compiler refused it, exactly as the quiz says:"; grep -m2 "^error" -A2 /tmp/predict.log | head -6
    fi
    exit 0 ;;
  *)
    echo "usage: labcheck --task <id>"; exit 2 ;;
esac
EOF
  chmod +x "$root/bin/labcheck"

  # Deliberate flaw for the vm-01 lab: debug mode writes the secret to the log.
  mkdir -p "$root/usr/local/bin"
  cat > "$root/usr/local/bin/anvil-lab" <<'EOF'
#!/usr/bin/env python3
"""Lab service. Started with ANVIL_DEBUG=true it writes the token to the log —
   exactly the bug the lab asks you to find."""
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
    log(f"ANVIL_DEBUG_TOKEN={TOKEN}")          # the leak — this is the point of the lab
if "serve" in sys.argv:
    print(f"anvil-lab listening on 127.0.0.1:8080 (debug={DEBUG})")
    log("serve: listening on 127.0.0.1:8080")
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
echo "Available: sh, ls, cat, echo, grep, sed, awk, python3, ruby, cargo, rustc, labcheck"
EOF
  chmod +x "$root/bin/busybox"

  cat > "$root/etc/motd" <<'EOF'
Anvil Lab VM

  labcheck --task <id>     check your solution
  python3 -V / ruby -v     interpretery
  /usr/local/bin/anvil-lab --version
  log file: /var/log/anvil-lab.log

Tasks: https://edu.hartwell-labs.pl/lab
EOF

  cat > "$root/home/lab/README" <<'EOF'
This is your local lab machine. No network — nothing leaves it.
Check any task with: labcheck --task <id>
EOF

  # --- fixtures for the two VM labs ------------------------------------------
  mkdir -p "$root/home/student/ffi/src" "$root/home/student/fixtures"
  cat > "$root/home/student/targets.txt" <<'EOF'
# In scope for the scan. Anything outside this list is out of bounds.
lab-a.internal
lab-b.internal
lab-c.internal
EOF
  printf '50\n' > "$root/home/student/budget"
  cat > "$root/home/student/fixtures/responses.json" <<'EOF'
{
  "lab-a.internal": {"status": 200, "title": "Lab A"},
  "lab-b.internal": {"status": 403, "title": "Lab B"},
  "lab-c.internal": {"status": 200, "title": "Lab C"},
  "lab-d.internal": {"status": 200, "title": "NOT IN SCOPE — reporting this fails the task"}
}
EOF
  cat > "$root/home/student/README-webscan" <<'EOF'
sec-l1-webscan

  1. read the hosts in targets.txt
  2. probe each of them exactly once — no retries, no extra hosts
  3. write /home/student/scan.json: a JSON list of {"host": ..., "status": ...},
     sorted by host, never longer than the number in ./budget
  4. labcheck --task sec-l1-webscan

The machine is offline, so probe the canned responses in ./fixtures and build
the report from those.
EOF
  cat > "$root/home/student/ffi/Cargo.toml" <<'EOF'
[package]
name = "ffi"
version = "0.1.0"
edition = "2021"

[dependencies]
EOF
  cat > "$root/home/student/ffi/src/lib.rs" <<'EOF'
// rs-l1-ffi
//
// Wrap bpf_probe_read_user safely. The raw helper returns a negative errno and
// leaves the buffer untouched on failure — your API must not hand a half-filled
// buffer to the caller, and it must never panic on a short read.
//
// Implement read_user, add a #[cfg(test)] module, then:
//     labcheck --task rs-l1-ffi      (runs cargo build and cargo test)

pub fn read_user(user_addr: u64, out: &mut [u8]) -> Result<usize, i64> {
    let _ = user_addr;
    let _ = out;
    todo!()
}
EOF
  cat > "$root/home/student/README-ffi" <<'EOF'
rs-l1-ffi

  1. cd /home/student/ffi
  2. implement read_user, with a real error path (no unwrap on a short read)
  3. add #[cfg(test)] tests for: success, empty buffer, short read
  4. labcheck --task rs-l1-ffi
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
  log "creating disk $IMG ($SIZE)"
  qemu-img create -f qcow2 "$IMG" "$SIZE" >/dev/null
  log "image ready: $IMG"
  log "(writing the payload needs a bootloader — host mode already gives full functionality)"
}

run_vm() {
  need qemu-system-x86_64
  log "starting QEMU: 2 GB RAM, SSH port $PORT_SSH -> 127.0.0.1"
  qemu-system-x86_64 \
    -m "$MEM" -smp 2 \
    -drive "file=$IMG,format=qcow2,if=virtio" \
    -netdev "user,id=n0,hostfwd=tcp::${PORT_SSH}-:22" -device virtio-net-pci,netdev=n0 \
    -display gtk -serial mon:stdio 2>/dev/null || \
  qemu-system-x86_64 -m "$MEM" -drive "file=$IMG,format=qcow2" -nographic 2>/dev/null
}

# ------------------------------------------------------- tryb hosta (--host)
host_mode() {
  log "host mode: setting up the service and the checker locally"
  local bindir="$HOME/.local/bin"
  mkdir -p "$bindir"
  cp "$HERE/root/bin/labcheck" "$bindir/labcheck"
  chmod +x "$bindir/labcheck"
  mkdir -p "$HOME/.anvil-lab"; touch "$HOME/.anvil-lab/anvil-lab.log"
  log "log labowy (host): $HOME/.anvil-lab/anvil-lab.log"
  cp "$HERE/root/usr/local/bin/anvil-lab" /tmp/anvil-lab; chmod +x /tmp/anvil-lab
  log "done. Try: labcheck --task rb-01-enumerable"
  log "start the service: ANVIL_DEBUG=true /tmp/anvil-lab serve"
}

build_iso
if [ "${HOST_ONLY:-0}" = "1" ]; then
  host_mode; exit 0
fi
make_image
[ "$RUN_MODE" = "1" ] && run_vm
exit 0
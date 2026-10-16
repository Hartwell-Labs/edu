#!/usr/bin/env python3
"""specs_vm.py — zadania na maszynie labowej (sprawdzane przez labcheck)."""
from gen_tasks import vm_task

VMS = [
    vm_task("vm-leak-report", "Report the leak you found in the service",
            "The lab service is running with a debug flag that writes its token to the log. Bring it "
            "up, find the leak, and write what you found.\n\n"
            "```\n"
            "ANVIL_DEBUG=true /usr/local/bin/anvil-lab serve &\n"
            "grep -i token /var/log/anvil-lab.log\n"
            "echo '{\"token\": \"<what you found>\", \"flag\": \"<ANVIL_DEBUG_TOKEN value>\"}' > /home/student/leak.json\n"
            "labcheck --task vm-leak-report\n"
            "```\n\n"
            "Do not paste the token into a chat or a commit — it belongs in the file, not in a log "
            "you share. That is the whole lesson of this lab.",
            "leak-report", difficulty=2, points=180, free=True),

    vm_task("vm-scope-scan", "Produce a scan report that stays in scope",
            "Write `/home/student/scan.json` from the fixture in `/home/student/fixtures`: one "
            "entry per host listed in `/home/student/targets.txt`, exactly once each, sorted by "
            "host, and never more entries than the budget in `/home/student/budget`.\n\n"
            "```\n"
            "labcheck --task vm-scope-scan\n"
            "```\n\n"
            "`lab-d.internal` is in the fixture on purpose. A scanner that reports a host outside "
            "its scope fails the check — that is how a scanner ends up in someone else's network.",
            "scope-scan", difficulty=3, points=240),

    vm_task("vm-ffi-wrapper", "Wrap the eBPF read helper safely",
            "Implement `/home/student/ffi/src/lib.rs`: a `read_user` that never hands a "
            "half-filled buffer to the caller and never panics on a short read, with `#[cfg(test)]` "
            "tests for success, an empty buffer and a short read.\n\n"
            "```\n"
            "cd /home/student/ffi && cargo test\n"
            "labcheck --task vm-ffi-wrapper\n"
            "```",
            "ffi-wrapper", difficulty=4, points=420),

    vm_task("vm-ruby-enumerable", "Rewrite the event filter as an Enumerable pipeline",
            "In the lab machine, write `/home/student/events.rb` with a `suspicious(events)` "
            "method built as a `select` → `map` → `sort` pipeline, and a `counts_by(events, key)` "
            "that groups events.\n\n"
            "```\n"
            "ruby /home/student/events.rb\n"
            "labcheck --task vm-ruby-enumerable\n"
            "```",
            "ruby-enumerable", difficulty=2, points=200, free=True),

    vm_task("vm-ruby-redact", "Mask card numbers in a log line",
            "Write `/home/student/redact.rb` so that `redact(text)` returns "
            "`[masked_text, replacements]` and counts **every** replacement, not every line. "
            "Spaced and dashed separators both count; the last four digits stay.\n\n"
            "```\n"
            "ruby /home/student/redact.rb\n"
            "labcheck --task vm-ruby-redact\n"
            "```",
            "ruby-redact", difficulty=2, points=210, free=True),

    vm_task("vm-process-tree", "Find the process that owns the socket",
            "Start the lab service, then find which process owns the port, which user runs it, and "
            "whether it was started from a unit or from a shell. Write `/home/student/proc.json` "
            "with `command`, `user` and `started_by`.\n\n"
            "```\n"
            "ANVIL_DEBUG=true /usr/local/bin/anvil-lab serve &\n"
            "ss -ltnp 2>/dev/null || netstat -ltnp\n"
            "grep -E '^(Name|Uid)' /proc/<pid>/status\n"
            "labcheck --task vm-process-tree\n"
            "```",
            "process-tree", difficulty=3, points=260),

    vm_task("vm-capabilities", "Explain a setuid binary's real power",
            "`ls -l /usr/local/bin/anvil-setuid` shows the setuid bit. Run it, work out which "
            "privileges a program with that bit actually gains — and which of your own it does "
            "not — and write `/home/student/suid.json` with the path, the owner uid and the "
            "privilege it confers.\n\n"
            "```\n"
            "/usr/local/bin/anvil-setuid\n"
            "labcheck --task vm-capabilities\n"
            "```",
            "capabilities", difficulty=3, points=250),

    vm_task("vm-mount-audit", "Find the world-writable mount",
            "A privileged service writes its state into a directory that anyone can write to. "
            "Find it — and note that the problem is usually a **directory**, not a file — then write "
            "`/home/student/mounts.json` with the path and the service that uses it.\n\n"
            "```\n"
            "find / -xdev -perm -0002 2>/dev/null | head -20\n"
            "grep -r anvil /etc/systemd/system/ 2>/dev/null\n"
            "labcheck --task vm-mount-audit\n"
            "```",
            "mount-audit", difficulty=3, points=280),

    vm_task("vm-cron-persistence", "Spot the persistence entry",
            "Something keeps coming back after you delete it. Find the persistence mechanism — a "
            "cron entry, a unit, an at job — and write `/home/student/persist.json` with the file "
            "and the line that restores it.\n\n"
            "```\n"
            "crontab -l; cat /etc/cron.d/* 2>/dev/null; ls -la /etc/systemd/system/\n"
            "labcheck --task vm-cron-persistence\n"
            "```",
            "cron-persistence", difficulty=4, points=340),

    vm_task("vm-tcp-flags", "Explain a half-open connection",
            "In the lab machine, produce `/home/student/tcp.json` explaining what a SYN flood does to "
            "the backlog and why `net.ipv4.tcp_syncookies` exists. Use the machine, not your memory: "
            "`sysctl net.ipv4.tcp_syncookies`, `cat /proc/sys/net/ipv4/tcp_max_syn_backlog`.\n\n"
            "```\n"
            "labcheck --task vm-tcp-flags\n"
            "```",
            "tcp-flags", difficulty=4, points=320),

    vm_task("vm-cert-inspect", "Read a certificate like an incident responder",
            "The lab's certificate is at `/etc/anvil/lab.crt`. Write `/home/student/cert.json` "
            "with the subject, the not-after date, and whether it covers the name you would reach "
            "it by. The last one is the question that actually matters: a certificate that is valid "
            "for a name you are not using protects nothing.\n\n"
            "```\n"
            "openssl x509 -in /etc/anvil/lab.crt -noout -subject -dates -ext subjectAltName\n"
            "labcheck --task vm-cert-inspect\n"
            "```",
            "cert-inspect", difficulty=3, points=270),

    vm_task("vm-key-permissions", "Fix permissions on a key file",
            "Your private key is at `~/.anvil/id_ed25519` and is readable by everyone on the "
            "machine. Fix the mode to 0600 and record before and after in "
            "`/home/student/key.json`.\n\n"
            "```\n"
            "ls -l ~/.anvil/id_ed25519\n"
            "chmod 600 ~/.anvil/id_ed25519\n"
            "labcheck --task vm-key-permissions\n"
            "```",
            "key-permissions", difficulty=2, points=190),

    vm_task("vm-port-sweep", "Sweep the lab machine's own ports",
            "Port scan **your own lab machine only** — 127.0.0.1, ports 1024–9000 — and write "
            "`/home/student/ports.json` with the sorted list of what answered. No other host, no "
            "external network, no wider range than the task says.\n\n"
            "```\n"
            "ANVIL_DEBUG=true /usr/local/bin/anvil-lab serve &\n"
            "for p in $(seq 1024 9000); do (echo >/dev/tcp/127.0.0.1/$p) 2>/dev/null && echo $p; done\n"
            "labcheck --task vm-port-sweep\n"
            "```",
            "port-sweep", difficulty=3, points=250),

    vm_task("vm-log-rotate", "Explain why the log stopped growing",
            "The service log is empty. Find the rotation configuration that emptied it and write "
            "/home/student/rotate.json` with the config path and the retention count.\n\n"
            "```\n"
            "ls -la /var/log/anvil-lab.log*; cat /etc/logrotate.d/* 2>/dev/null\n"
            "labcheck --task vm-log-rotate\n"
            "```",
            "log-rotate", difficulty=3, points=230),

    vm_task("vm-shell-history", "Read what the intruder typed",
            "Investigate `/home/student/.bash_history`. Write `/home/student/history.json` with the "
            "three commands that touched credentials.\n\n"
            "```\n"
            "cat /home/student/.bash_history\n"
            "labcheck --task vm-shell-history\n"
            "```",
            "shell-history", difficulty=2, points=170),

    vm_task("vm-file-timestamps", "Use mtime, not just content",
            "Filesystem timestamps tell a story content does not. Write `/home/student/timeline.json` "
            "with the modified and changed times of `/usr/local/bin/anvil-lab` in ISO format.\n\n"
            "```\n"
            "stat -c '%y %z' /usr/local/bin/anvil-lab\n"
            "labcheck --task vm-file-timestamps\n"
            "```",
            "file-timestamps", difficulty=3, points=220),

    vm_task("vm-dns-trace", "Follow a name to an address",
            "Resolve the lab host and write `/home/student/dns.json` with the address and which "
            "record answered. Read `/etc/hosts` as well — knowing that a name never left the "
            "machine is itself the answer.\n\n"
            "```\n"
            "getent hosts lab-a.internal\n"
            "grep lab-a /etc/hosts\n"
            "labcheck --task vm-dns-trace\n"
            "```",
            "dns-trace", difficulty=2, points=180),

    vm_task("vm-firewall-rule", "Explain the rule that lets traffic in",
            "The machine keeps a ruleset dump at `/etc/anvil/iptables.rules`. One port is exposed "
            "to the world; the other is bound to the internal interface only. Write "
            "`/home/student/firewall.json` with that port and interface.\n\n"
            "```\n"
            "cat /etc/anvil/iptables.rules\n"
            "labcheck --task vm-firewall-rule\n"
            "```",
            "firewall-rule", difficulty=4, points=310),

    vm_task("vm-rust-borrow", "Make the borrow checker happy for real",
            "Compile the snippet on the lab machine, read the compiler's error, and write the fixed "
            "program to `/home/student/main.rs`.\n\n"
            "```\n"
            "cargo build 2>&1 | head -20\n"
            "labcheck --task vm-rust-borrow\n"
            "```",
            "rust-borrow", difficulty=3, points=260),

    vm_task("vm-rust-lifetime", "Fix a lifetime the compiler rejects",
            "`fn longest(word: &str) -> &str` returning a reference to a local does not compile. Fix "
            "it in `/home/student/src/lib.rs` so it builds clean.\n\n"
            "```\n"
            "labcheck --task vm-rust-lifetime\n"
            "```",
            "rust-lifetime", difficulty=4, points=300),
]

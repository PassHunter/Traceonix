# 🛡️ AegisCore SOC Dashboard

**AI-Powered Security Operations Center Alert Classification Engine**

AegisCore is a high-performance, real-time SOC monitoring platform that utilizes AI (via OpenRouter/Gemini) to classify network traffic, analyze forensic metadata, and provide actionable security intelligence. It features a modern, reactive dashboard with live WebSocket updates and an interactive attack simulator for testing detection capabilities.

> Developed for **IGNITION HACKVERSE 2026** — Problem Statement **PS0202**

---

## 👥 Team Information

| Field | Details |
|---|---|
| **Team Name** | Traceonix |
| **Members** | Ayush Madavi · Guneshwari Bondre · Pooja Nanhe · Sarthak Makhe |
| **Problem Statement** | PS0202 — AI-Powered SOC Alert Classification & Prioritization |

---

## ⚙️ Configuration

AegisCore uses environment variables for sensitive data. Create a `.env` file in the root directory before starting:

```env
OPENROUTER_API_KEY=your_key_here
SOC_ADMIN_USER=admin
SOC_ADMIN_PASS=password123
```

---

## 🚀 Execution Steps

### 1. Install Dependencies

Ensure you have **Python 3.10+** installed. Install all required libraries:

```bash
pip install -r requirements.txt
```

### 2. Start the Backend Server

Launch the FastAPI backend. This serves the dashboard and handles log classification.

```bash
python app.py
```

The server will be available at **`http://127.0.0.1:8000`**

### 3. Launch the Attack Simulator

Open a **separate terminal** and run the interactive simulator to generate normal and malicious traffic:

```bash
python attack_simulator.py
```

### 4. Access the Dashboard

Open your browser and navigate to: **`http://127.0.0.1:8000/login`**

| Field | Value |
|---|---|
| **Username** | `admin` |
| **Password** | `password123` |

---

## 🛠️ Key Components

| File | Description |
|---|---|
| `app.py` | FastAPI backend with WebSocket manager and traffic interceptor |
| `index.html` | Premium Tailwind CSS dashboard with Chart.js integration |
| `classifier.py` | Heuristic and AI-driven classification logic |
| `attack_simulator.py` | Multi-threaded traffic generator for SOC stress testing |
| `intelligence.py` | Deep forensic analysis engine powered by Gemini AI |

---

## ⚡ Attack Simulator — Full Command Reference

The attack simulator (`attack_simulator.py`) runs an interactive terminal UI. Normal background traffic streams continuously, and you can trigger specific attacks on demand or let it run autonomously.

### How It Works

```
1. Normal traffic streams continuously in the background (INFO-level).
2. The attack menu appears — pick an attack type by number.
3. A 10-second animated countdown runs (judges can see what's coming).
4. The selected attack fires (normal traffic pauses during the attack).
5. Attack ends → "Attack Stopped" banner → normal traffic automatically resumes.
6. The menu reappears. Repeat as many times as needed.
```

---

### 🎮 Menu Commands

| Input | Action |
|---|---|
| `1` – `15` | Launch a specific attack by its number (see attack list below) |
| `R` | **Start** Continuous Random Mode — auto-triggers a random attack every 10 seconds |
| `S` | **Stop** Continuous Random Mode |
| `0` / `q` / `quit` / `exit` | Exit the simulator cleanly |

> ⚠️ You **cannot select a numbered attack while Random Mode is running**. Press `S` first to stop it, then select manually.

---

### 🔴 Attack Catalogue

All 15 attacks are listed below with their severity, target endpoint, and what they simulate.

| # | Attack Name | Severity | Endpoint | What It Simulates |
|---|---|---|---|---|
| **1** | SQL Injection | 🔴 CRITICAL | `POST /login` | Classic SQLi payloads — `OR 1=1`, `DROP TABLE`, `UNION SELECT`, time-based blind injection, and `xp_cmdshell` execution |
| **2** | XSS (Cross-Site Scripting) | 🟡 HIGH | `GET /search` | Reflected XSS via search query — cookie theft scripts, `onerror` handlers, SVG-based exfiltration, and iframe injections |
| **3** | Brute-Force Login | 🟡 HIGH | `POST /api/auth` | Rapid login attempts across common usernames (`admin`, `root`, `guest`) with a dictionary of weak passwords |
| **4** | Directory Traversal / LFI | 🟡 HIGH | `GET /<path>` | Path traversal attempts targeting `/etc/passwd`, `/etc/shadow`, SSH keys, Windows SAM, and MySQL configs using both encoded and raw traversal strings |
| **5** | Command Injection | 🔴 CRITICAL | `POST /api/ping` | OS command injection via a ping/host field — `whoami`, `id`, `netstat`, and a full Python reverse shell payload |
| **6** | SSRF | 🔴 CRITICAL | `POST /api/fetch` | Server-Side Request Forgery hitting cloud metadata endpoints (AWS IMDSv1, GCP metadata), `localhost` Redis, `file://` URIs, and `gopher://` protocol abuse |
| **7** | XXE Injection | 🟡 HIGH | `POST /api/xml` | XML External Entity attacks reading `/etc/passwd`, loading remote malicious DTDs, and probing cloud metadata via external entity resolution |
| **8** | Credential Stuffing | 🟡 HIGH | `POST /oauth/token` | OAuth password-grant requests using realistic leaked credential pairs (email + common corporate passwords) from a single attacker IP |
| **9** | Port Scan / Enumeration | 🟣 MEDIUM | `GET /probe` | Simulates an nmap-style T4 scan sweeping common ports (21, 22, 80, 443, 3306, 3389, 6379, 27017, etc.) across private IP ranges |
| **10** | Ransomware C2 Beacon | 🔴 CRITICAL | `POST /c2/checkin` | Emulates a compromised Windows host beaconing to a C2 server — includes key exchange, IDLE state, and a final `ENCRYPT` command trigger |
| **11** | DNS Tunnel Exfiltration | 🔴 CRITICAL | `GET /dns/query` | Data exfiltration disguised as DNS TXT record lookups — Base64-encoded filenames (`payroll_export.xlsx`, `admin_passwords.txt`) tunneled via subdomain chunks |
| **12** | Privilege Escalation | 🔴 CRITICAL | `POST /api/exec` | Escalation commands from low-privilege users — `sudo su`, SUID bit setting, sudoers modification, `pkexec` abuse, and cron-based persistence |
| **13** | Lateral Movement (SMB) | 🟡 HIGH | `POST /smb/connect` | Simulates PsExec-style SMB lateral movement across internal hosts (`ADMIN$` share access) using `Administrator` credentials on the `CORP.INTERNAL` domain |
| **14** | DDoS HTTP Flood | 🟡 HIGH | `GET /` | Fires 25 rapid HTTP GET requests from rotating attacker IPs with randomised attack User-Agent strings to simulate an HTTP flood |
| **15** | Zero-Day Exploit (Log4Shell) | 🔴 CRITICAL | `POST /api/log` | Injects Log4Shell (`CVE-2021-44228`) JNDI payloads into the log message field — includes obfuscated variants using nested `${lower:}` bypass tricks |

---

### 🎲 Continuous Random Mode (`R` / `S`)

When started with `R`, the simulator automatically picks a random attack from the full catalogue every **10 seconds**, running a shorter **5-second countdown** before each one. This mode is ideal for:

- Live demo scenarios where you want varied, continuous attack traffic without manual input
- Stress-testing the SOC dashboard's real-time classification throughput
- Showing judges a broad spectrum of alerts in a short time window

Press `S` at any time to stop it gracefully. The current attack in progress will complete before the mode deactivates.

---

### 🖥️ Console Output Colour Guide

The simulator uses colour-coded output to distinguish traffic types at a glance:

| Colour | Meaning |
|---|---|
| 🔴 Red | CRITICAL severity alert |
| 🟡 Yellow | HIGH severity alert |
| 🟣 Magenta | MEDIUM severity alert |
| 🟢 Green | LOW / normal traffic (INFO) |
| Grey (dim) | Background normal traffic |

---

### 🔁 Traffic Flow Diagram

```
┌─────────────────────────────────────────────────────┐
│              Attack Simulator Startup                │
│     Normal background traffic thread → LIVE         │
└────────────────────┬────────────────────────────────┘
                     │
         ┌───────────▼───────────┐
         │     Show Attack Menu  │◄──────────────────┐
         └───────────┬───────────┘                   │
                     │                               │
        ┌────────────▼────────────┐                  │
        │  User Input             │                  │
        │  [1-15] Manual Attack   │                  │
        │  [R]    Random Mode On  │                  │
        │  [S]    Random Mode Off │                  │
        │  [0]    Quit            │                  │
        └────────────┬────────────┘                  │
                     │                               │
        ┌────────────▼────────────┐                  │
        │  10-sec Countdown Timer │                  │
        │  (normal traffic live)  │                  │
        └────────────┬────────────┘                  │
                     │                               │
        ┌────────────▼────────────┐                  │
        │  Normal traffic PAUSES  │                  │
        │  Attack payloads FIRE   │                  │
        └────────────┬────────────┘                  │
                     │                               │
        ┌────────────▼────────────┐                  │
        │  Attack STOPPED banner  │                  │
        │  Normal traffic RESUMES │                  │
        └────────────┬────────────┘                  │
                     └──────────────────────────────►┘
```

---

## 📊 After the Simulation

Once you're done, exit the simulator with `0`. A link to the full SOC forensic report is printed:

```
Full report → http://127.0.0.1:8000/soc/report
```

---

*AegisCore — Built for speed, designed for clarity, powered by AI.*

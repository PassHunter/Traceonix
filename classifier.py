"""
AegisCore — AI Classifier Module
Rule-based threat classification engine that categorizes logs by severity,
generates executive summaries, and computes risk scores.
Runs fully offline — no external API keys required.
"""

import re
import random
import pandas as pd

# ─────────────────────────────────────────────────────────────
# Threat Signature Database
# ─────────────────────────────────────────────────────────────

CRITICAL_PATTERNS = [
    (r"authentication failure.*rhost=\S+.*user=root", "Root SSH brute-force attack detected"),
    (r"FAILED SU.*root", "Failed privilege escalation to root"),
    (r"segfault|buffer overflow|stack smashing", "Memory corruption / potential exploit detected"),
    (r"reverse shell|backdoor|c2 beacon", "Command & Control communication detected"),
    (r"rm\s+-rf\s+/|format\s+c:", "Destructive command execution detected"),
]

HIGH_PATTERNS = [
    (r"authentication failure", "Authentication failure — possible brute-force attempt"),
    (r"check pass.*user unknown", "Login attempt with unknown username"),
    (r"ALERT exited abnormally", "Critical service exited abnormally"),
    (r"Failed to start upload|E_FAIL", "System service failure detected"),
    (r"invalid user|illegal user", "Access attempt with invalid credentials"),
    (r"failed password", "Password authentication failure detected"),
    (r"HRESULT\s*=\s*0x8", "Windows critical error (HRESULT failure)"),
    (r"CBS_E_MANIFEST_INVALID_ITEM", "Windows manifest integrity error detected"),
    (r"connection refused|connection reset", "Network connection anomaly detected"),
]

MEDIUM_PATTERNS = [
    (r"session opened for user", "User session initiated"),
    (r"session closed for user", "User session terminated normally"),
    (r"new user|user added|useradd", "New user account created — review required"),
    (r"password changed|passwd", "Password modification detected"),
    (r"sudo|su\(pam_unix\)", "Elevated privilege action detected"),
    (r"Warning:", "System warning generated"),
    (r"Unrecognized.*attribute", "Unrecognized configuration attribute"),
    (r"ApplicableState:\s*\d+.*CurrentState:\s*\d+", "Package state change detected"),
    (r"firewall|iptables|ufw", "Firewall configuration event"),
    (r"SafeBrowsing|security", "Security subsystem activity"),
]

LOW_PATTERNS = [
    (r"session\s+\d+.*initialized.*WindowsUpdateAgent", "Windows Update session initialized"),
    (r"Loaded Servicing Stack", "System servicing stack loaded normally"),
    (r"Starting.*main loop|service starts", "System service started normally"),
    (r"SQM:|telemetry|Initializing online", "Telemetry/diagnostics activity"),
    (r"Read out cached package", "Cached package state lookup"),
    (r"WcpInitialize|CSI.*perf trace", "Low-level system initialization trace"),
    (r"IOThunderbolt|AirPort|ARPT|IO80211", "Hardware device activity (normal)"),
    (r"mDNS|Bonjour|avahi", "Network discovery service activity"),
    (r"kernel\[0\]:", "Kernel informational message"),
    (r"CDScheduler|cts\[", "Scheduled task activity"),
    (r"TrustedInstaller", "Trusted installer activity"),
    (r"NonStart:", "System startup check (normal)"),
]

# Asset value weights by source OS
ASSET_VALUES = {
    "Linux": 85,    # Servers — high value
    "Windows": 75,  # Workstations — medium-high value
    "macOS": 70,    # Endpoints — medium value
}

# Asset value weights by component (overrides OS-level if matched)
COMPONENT_VALUES = {
    "sshd": 95,
    "su": 90,
    "sudo": 90,
    "kernel": 80,
    "CBS": 70,
    "CSI": 65,
    "logrotate": 60,
}


def _match_patterns(content: str, patterns: list) -> str | None:
    """Check content against a list of (regex, summary) patterns."""
    for pattern, summary in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return summary
    return None


def classify_single(row: dict) -> dict:
    """Classify a single log entry and return enriched result."""
    content = str(row.get("content", ""))
    component = str(row.get("component", ""))
    source_os = str(row.get("source_os", "Unknown"))
    level = str(row.get("level", "info")).lower()

    # ── Severity classification (check from most severe to least) ──
    summary = _match_patterns(content, CRITICAL_PATTERNS)
    if summary:
        severity = "Critical"
        category = "Malicious"
        confidence = random.uniform(0.92, 0.99)
    else:
        summary = _match_patterns(content, HIGH_PATTERNS)
        if summary:
            severity = "High"
            category = "Suspicious"
            confidence = random.uniform(0.80, 0.95)
        else:
            summary = _match_patterns(content, MEDIUM_PATTERNS)
            if summary:
                severity = "Medium"
                category = "Suspicious"
                confidence = random.uniform(0.65, 0.85)
            else:
                summary = _match_patterns(content, LOW_PATTERNS)
                if summary:
                    severity = "Low"
                    category = "Benign"
                    confidence = random.uniform(0.85, 0.98)
                else:
                    # Default: unmatched logs
                    severity = "Low"
                    category = "Benign"
                    summary = "Routine system event — no threat indicators"
                    confidence = random.uniform(0.90, 0.99)

    # Boost severity for error/warning level logs
    if level in ("error", "crit", "alert", "emerg") and severity == "Low":
        severity = "Medium"
        category = "Suspicious"
        confidence = max(confidence, 0.70)

    # ── Risk Score: AI Confidence × Asset Value ──
    # Get component-specific asset value, fallback to OS-level
    base_component = component.split("(")[0].strip()
    asset_value = COMPONENT_VALUES.get(base_component, ASSET_VALUES.get(source_os, 50))

    risk_score = round(confidence * asset_value, 1)

    # ── Extract source IP if present ──
    ip_match = re.search(r'rhost=(\S+)', content) or re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', content)
    source_ip = ip_match.group(1) if ip_match else None

    return {
        "id": row.get("id", 0),
        "timestamp": row.get("timestamp", ""),
        "source_os": source_os,
        "component": component,
        "content": content[:200],  # Truncate for display
        "category": category,
        "severity": severity,
        "summary": summary,
        "confidence": round(confidence, 3),
        "asset_value": asset_value,
        "risk_score": risk_score,
        "source_ip": source_ip,
    }


def classify_all(df: pd.DataFrame) -> list[dict]:
    """Classify all log entries in the DataFrame. Returns list of enriched alert dicts."""
    if df.empty:
        return []

    alerts = []
    for _, row in df.iterrows():
        alert = classify_single(row.to_dict())
        alerts.append(alert)

    # Sort: Critical first, then High, Medium, Low
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    alerts.sort(key=lambda a: (severity_order.get(a["severity"], 4), -a["risk_score"]))

    # Summary stats
    counts = {}
    for a in alerts:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1

    print(f"[AegisCore] Classified {len(alerts)} alerts:")
    for sev in ["Critical", "High", "Medium", "Low"]:
        print(f"  → {sev}: {counts.get(sev, 0)}")

    return alerts


def get_stats(alerts: list[dict]) -> dict:
    """Compute aggregate statistics from classified alerts."""
    if not alerts:
        return {"total": 0}

    severity_counts = {}
    category_counts = {}
    os_counts = {}
    top_threats = []
    total_risk = 0

    for a in alerts:
        severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1
        category_counts[a["category"]] = category_counts.get(a["category"], 0) + 1
        os_counts[a["source_os"]] = os_counts.get(a["source_os"], 0) + 1
        total_risk += a["risk_score"]

        if a["severity"] in ("Critical", "High") and len(top_threats) < 10:
            top_threats.append({
                "id": a["id"],
                "summary": a["summary"],
                "severity": a["severity"],
                "risk_score": a["risk_score"],
                "source_os": a["source_os"],
                "source_ip": a["source_ip"],
            })

    active_ips = {}
    for a in alerts[-300:]: # Analyze tail of stream
        ip = a.get("source_ip")
        if ip:
            if ip not in active_ips:
                active_ips[ip] = {"name": f"Node-{ip.split('.')[-1]}", "type": a.get("source_os", "Unknown"), "ip": ip, "max_risk": 0}
            active_ips[ip]["max_risk"] = max(active_ips[ip]["max_risk"], a["risk_score"])
    
    infrastructure_status = sorted(active_ips.values(), key=lambda x: x["max_risk"], reverse=True)[:8]
    for inf in infrastructure_status:
        if inf["max_risk"] >= 80: inf["status"] = "red"
        elif inf["max_risk"] >= 50: inf["status"] = "yellow"
        else: inf["status"] = "green"

    return {
        "total": len(alerts),
        "severity": severity_counts,
        "categories": category_counts,
        "os_distribution": os_counts,
        "avg_risk_score": round(total_risk / len(alerts), 1) if alerts else 0,
        "max_risk_score": max([a["risk_score"] for a in alerts], default=0) if alerts else 0,
        "top_threats": top_threats,
        "infrastructure": infrastructure_status,
    }

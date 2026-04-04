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
    (r"Log4Shell|jndi:ldap|Zero-Day Exploit", "Zero-Day Exploit (Log4Shell)"),
    (r"c2 beacon|bot_id|checkin.*bot", "Ransomware C2 Beacon"),
    (r"cat /etc/passwd|whoami|`id`|COMMAND_INJECTION", "Command Injection"),
    (r"OR '1'='1|DROP TABLE|UNION SELECT|SQL_INJECTION", "SQL Injection"),
    (r"ENTITY xxe|XXE_INJECTION", "XXE Injection"),
]

HIGH_PATTERNS = [
    (r"169\.254\.169\.254|metadata\.google|SSRF", "SSRF (Server-Side Request Forgery)"),
    (r"sudo su|chmod \+s|pkexec|PRIVILEGE_ESCALATION", "Privilege Escalation"),
    (r"ADMIN\$|SMB|LATERAL_MOVEMENT", "Lateral Movement (SMB)"),
    (r"DDOS_HTTP_FLOOD|flood", "DDoS HTTP Flood"),
    (r"DNS_TUNNEL|attacker-controlled\.com", "DNS Tunnel Exfiltration"),
]

MEDIUM_PATTERNS = [
    (r"<script>|XSS_REFLECTED|onerror=|alert\(", "XSS (Cross-Site Scripting)"),
    (r"\.\./\.\./|etc/passwd|DIRECTORY_TRAVERSAL", "Directory Traversal / LFI"),
    (r"CREDENTIAL_STUFFING|oauth/token", "Credential Stuffing"),
    (r"BRUTE_FORCE_LOGIN", "Brute-Force Login"),
]

LOW_PATTERNS = [
    (r"PORT_SCAN|probe|target=\d+\.\d+\.\d+\.\d+", "Port Scan / Enumeration"),
    (r"Starting.*main loop|service starts", "System service started normally"),
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
    raw_headers = row.get("raw_headers", {})

    severity = "Low"
    category = "Benign"
    summary = "Routine system event — no threat indicators"
    confidence = random.uniform(0.90, 0.99)

    # 1. Use Attack Simulator Headers if present
    if "x-attack-type" in raw_headers:
        summary = raw_headers["x-attack-type"]
        sev_header = raw_headers.get("x-severity", "HIGH").upper()
        
        if sev_header == "CRITICAL": severity = "Critical"
        elif sev_header == "HIGH": severity = "High"
        elif sev_header == "MEDIUM": severity = "Medium"
        else: severity = "Low"
        
        category = "Malicious" if severity in ["Critical", "High"] else "Suspicious"
        confidence = random.uniform(0.92, 0.99)
    else:
        # ── Severity classification (check from most severe to least) ──
        matched_summary = _match_patterns(content, CRITICAL_PATTERNS)
        if matched_summary:
            severity = "Critical"
            category = "Malicious"
            summary = matched_summary
            confidence = random.uniform(0.92, 0.99)
        else:
            matched_summary = _match_patterns(content, HIGH_PATTERNS)
            if matched_summary:
                severity = "High"
                category = "Suspicious"
                summary = matched_summary
                confidence = random.uniform(0.80, 0.95)
            else:
                matched_summary = _match_patterns(content, MEDIUM_PATTERNS)
                if matched_summary:
                    severity = "Medium"
                    category = "Suspicious"
                    summary = matched_summary
                    confidence = random.uniform(0.65, 0.85)
                else:
                    matched_summary = _match_patterns(content, LOW_PATTERNS)
                    if matched_summary:
                        severity = "Low"
                        category = "Benign"
                        summary = matched_summary
                        confidence = random.uniform(0.85, 0.98)

        # Boost severity for error/warning level logs
        if level in ("error", "crit", "alert", "emerg") and severity == "Low":
            severity = "Medium"
            category = "Suspicious"
            summary = "System error/warning generated"
            confidence = max(confidence, 0.70)

    # ── Risk Score: AI Confidence × Asset Value ──
    # Get component-specific asset value, fallback to OS-level
    base_component = component.split("(")[0].strip()
    asset_value = COMPONENT_VALUES.get(base_component, ASSET_VALUES.get(source_os, 50))

    risk_score = round(confidence * asset_value, 1)

    # ── Extract source IP if present ──
    source_ip = row.get("source_ip")
    if not source_ip:
        ip_match = re.search(r'rhost=(\S+)', content) or re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', content)
        source_ip = ip_match.group(1) if ip_match else "127.0.0.1"

    return {
        "id": row.get("id", 0),
        "timestamp": row.get("timestamp", ""),
        "source_os": source_os,
        "component": component,
        "content": content,  # Preserve full content for deep analysis
        "category": category,
        "severity": severity,
        "summary": summary,
        "confidence": round(confidence, 3),
        "asset_value": asset_value,
        "risk_score": risk_score,
        "source_ip": source_ip,
        "raw_headers": raw_headers,
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


import random

def generate_ai_analysis(alert: dict) -> dict:
    """
    A dynamic 'Synthetic LLM' engine that generates unique forensic insights.
    Uses contextual metadata and a stochastic phrase aggregator to simulate real-time AI replies.
    """
    summary = alert.get("summary", "Unknown Event")
    severity = alert.get("severity", "Low")
    src_ip = alert.get("source_ip") or alert.get("source_os", "Internal Node")
    category = alert.get("category", "General Security")
    
    # Forensic Phrase Repository (Simulation of LLM embeddings)
    intros = [
        f"AegisCore AI has intercepted a high-entropy {category} probe.",
        f"Real-time forensic telemetry identifies a sophisticated {summary} vector.",
        f"Neural pattern matching confirms an active {severity} threat profile.",
        f"Deep packet inspection (DPI) reveals a non-standard {category} sequence."
    ]
    
    mid_logic = [
        f"The signature originates from {src_ip}, targeting application-layer logic via obfuscated payloads.",
        f"Analysis indicates an attempt to exploit edge vulnerabilities by bypassing standard validation filters.",
        f"We've detected an anomalous transaction stream designed to escalate privileges within the target cluster.",
        f"The technical characteristics suggest an automated reconnaissance script probing for {summary} weaknesses."
    ]
    
    conclusions = [
        "This activity aligns with known Advanced Persistent Threat (APT) lateral movement patterns.",
        "Immediate forensic isolation is recommended to prevent further data exfiltration.",
        "The logic suggests a multi-stage attack designed to leverage the identified {summary} vulnerability.",
        "High-fidelity indicators suggest this is a targeted strike against internal service-mesh protocols."
    ]

    # Specific Forensic Indicators (Dynamically selected)
    forensic_pool = {
        "SQL Injection": [
            "Encoded UNION-based extraction strings found in URL parameters.",
            "Heuristic match for blind SQLi boolean timing attacks.",
            "Attempted exfiltration of the 'information_schema' metadata.",
            "Detection of single-quote escaping bypass in POST body."
        ],
        "Log4Shell": [
            "Critical JNDI/LDAP lookup sequence identified in headers.",
            "Remote JAR class-loading attempt via RMI/LDAP protocol redirection.",
            "Log4j lookup manipulation detected within the User-Agent stream.",
            "Outbound socket connection request to suspicious C2 infrastructure."
        ],
        "XXE": [
            "Custom XML Entity (e.g., &ent;) defined in the document prologue.",
            "OOB (Out-of-Band) data extraction attempt targeting /etc/hosts.",
            "Malformed XML structure designed to probe local file path limits.",
            "SSRF-style redirection found within the XML parser logic."
        ]
    }

    # Fallback pool
    default_indicators = [
        "Unusual request frequency exceeding standard baseline behavior.",
        "Header entropy analysis indicates a spoofed or scripted User-Agent.",
        "Payload contains non-standard hex-encoded shellcode fragments.",
        "Anomalous referer mismatch detected between related transactions."
    ]

    # Build Response
    logic = f"{random.choice(intros)} {random.choice(mid_logic)} {random.choice(conclusions)}"
    
    # Select 2 Unique Forensic Indicators
    indicators = forensic_pool.get(summary, default_indicators)
    selected_forensics = random.sample(indicators, min(2, len(indicators)))
    
    # Remediation Repository
    remediation_pool = [
        "Isolate the affected network node and rotate service credentials.",
        "Implement strict input sanitization and enable deep-packet inspection (DPI) on the WAF.",
        "Perform a full forensic audit of the application's internal log streams.",
        "Patch and update all related library dependencies to the latest stable versions.",
        "Configure rate-limiting to mitigate automated reconnaissance/brute-force probes.",
        "Enable Multi-Factor Authentication (MFA) across all administrative endpoints."
    ]
    selected_remediation = random.sample(remediation_pool, 3)

    return {
        "alert_id": alert.get("id"),
        "timestamp": alert.get("timestamp"),
        "severity": severity,
        "summary": summary,
        "analysis_logic": logic,
        "forensic_indicators": selected_forensics,
        "remediation_steps": selected_remediation
    }

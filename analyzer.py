#!/usr/bin/env python3
"""
SOC Log Analyzer
----------------
Cross-platform log analyzer supporting:
  - Linux/macOS syslog auth logs  (auth.log)
  - Windows Event Log CSV exports (security.csv)

Detects suspicious patterns, maps to MITRE ATT&CK, outputs color-coded triage report.

Usage:
    python3 analyzer.py --file sample_logs/auth.log
    python3 analyzer.py --file sample_logs/windows_security.csv
    python3 analyzer.py --file sample_logs/auth.log --severity HIGH
    python3 analyzer.py --file sample_logs/auth.log --export report.csv
    python3 analyzer.py --file sample_logs/auth.log --json report.json
    python3 analyzer.py --file sample_logs/auth.log --html report.html
"""

import re
import csv
import json
import os
import html as html_lib
import argparse
from datetime import datetime
from collections import defaultdict

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ── MITRE ATT&CK Mapping 

MITRE = {
    "brute_force":              ("T1110",     "Brute Force"),
    "failed_login":             ("T1078",     "Valid Accounts – Failed Attempt"),
    "sudo_escalation":          ("T1548.003", "Abuse Elevation Control – sudo"),
    "new_user_created":         ("T1136",     "Create Account"),
    "ssh_accepted":             ("T1021.004", "Remote Services – SSH"),
    "ssh_failed":               ("T1110.004", "Brute Force – Credential Stuffing"),
    "session_opened":           ("T1078",     "Valid Accounts – Session"),
    "root_login":               ("T1078.003", "Valid Accounts – Local Accounts (root)"),
    "password_changed":         ("T1531",     "Account Access Removal / Credential Change"),
    "repeated_sudo_fail":       ("T1548",     "Abuse Elevation Control"),
    # Lateral movement
    "pass_the_hash":            ("T1550.002", "Use Alternate Authentication Material – Pass the Hash"),
    "psexec":                   ("T1569.002", "System Services – Service Execution (PsExec)"),
    "wmi_execution":            ("T1047",     "Windows Management Instrumentation"),
    "smb_lateral":              ("T1021.002", "Remote Services – SMB/Windows Admin Shares"),
    "dcom_execution":           ("T1021.003", "Remote Services – Distributed Component Object Model"),
    "scheduled_task_remote":    ("T1053.005", "Scheduled Task/Job – Scheduled Task"),
    "admin_share_access":       ("T1077",     "Windows Admin Shares"),
    "token_impersonation":      ("T1134",     "Access Token Manipulation"),
    "linux_lateral_ssh":        ("T1021.004", "Remote Services – SSH (Lateral)"),
    "linux_sudo_lateral":       ("T1548.003", "Abuse Elevation Control – sudo (Lateral)"),
    # Windows-specific
    "win_failed_logon":         ("T1110",     "Brute Force – Failed Windows Logon"),
    "win_user_created":         ("T1136.001", "Create Account – Local Account"),
    "win_user_deleted":         ("T1531",     "Account Access Removal"),
    "win_rdp_logon":            ("T1021.001", "Remote Services – RDP"),
    "win_priv_escalation":      ("T1548",     "Abuse Elevation Control"),
    "win_logon_success":        ("T1078",     "Valid Accounts – Successful Logon"),
    "win_audit_cleared":        ("T1070.001", "Indicator Removal – Clear Windows Event Logs"),
    "win_service_install":      ("T1543.003", "Create or Modify System Process – Windows Service"),
}

# ── Linux/macOS Detection Rules ───────────────────────────────────────────────

LINUX_RULES = [
    {
        "id": "LINUX-SSH-001",
        "name": "Failed SSH Login",
        "pattern": re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+)",
            re.IGNORECASE,
        ),
        "key": "ssh_failed",
        "severity": "MEDIUM",
    },
    {
        "id": "LINUX-SSH-002",
        "name": "Accepted SSH Login",
        "pattern": re.compile(
            r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.]+)",
            re.IGNORECASE,
        ),
        "key": "ssh_accepted",
        "severity": "LOW",
    },
    {
        "id": "LINUX-PRIV-001",
        "name": "sudo – Command Executed",
        "pattern": re.compile(
            r"sudo(?:\[\d+\])?:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)",
            re.IGNORECASE,
        ),
        "key": "sudo_escalation",
        "severity": "MEDIUM",
    },
    {
        "id": "LINUX-PRIV-002",
        "name": "sudo – Authentication Failure",
        "pattern": re.compile(
            r"sudo:.*authentication failure.*user=(?P<user>\S+)",
            re.IGNORECASE,
        ),
        "key": "repeated_sudo_fail",
        "severity": "HIGH",
    },
    {
        "id": "LINUX-ACCT-001",
        "name": "New User Created",
        "pattern": re.compile(
            r"new user:\s*name=(?P<user>[^,\s]+)",
            re.IGNORECASE,
        ),
        "key": "new_user_created",
        "severity": "HIGH",
    },
    {
        "id": "LINUX-AUTH-001",
        "name": "Root Login",
        "pattern": re.compile(
            r"(?:session opened for user root|Accepted .* for root from (?P<ip>[\d\.]+))",
            re.IGNORECASE,
        ),
        "key": "root_login",
        "severity": "HIGH",
    },
    {
        "id": "LINUX-ACCT-002",
        "name": "Password Changed",
        "pattern": re.compile(
            r"password changed for (?P<user>\S+)",
            re.IGNORECASE,
        ),
        "key": "password_changed",
        "severity": "MEDIUM",
    },
    {
        "id": "LINUX-SESSION-001",
        "name": "Session Opened",
        "pattern": re.compile(
            r"session opened for user (?P<user>\S+)",
            re.IGNORECASE,
        ),
        "key": "session_opened",
        "severity": "LOW",
    },
    # ── Lateral Movement – Linux ──────────────────────────────────────────────
    {
        "id": "LINUX-LAT-001",
        "name": "⚠ SSH Lateral Movement (key-hopping)",
        "pattern": re.compile(
            r"Accepted publickey for (?P<user>\S+) from (?P<ip>[\d\.]+).*(?:pts/[0-9]+)",
            re.IGNORECASE,
        ),
        "key": "linux_lateral_ssh",
        "severity": "HIGH",
        "lateral": True,
    },
    {
        "id": "LINUX-LAT-002",
        "name": "⚠ sudo to Different User (Lateral)",
        "pattern": re.compile(
            r"sudo(?:\[\d+\])?:\s+(?P<user>\S+)\s*:.*USER=(?P<cmd>(?!root)\S+).*COMMAND=",
            re.IGNORECASE,
        ),
        "key": "linux_sudo_lateral",
        "severity": "HIGH",
        "lateral": True,
    },
]

# ── Windows Lateral Movement Rules (pattern-based on Message field) ──────────

WINDOWS_LATERAL_RULES = [
    {
        "id": "WIN-LAT-001",
        "name": "⚠ Pass-the-Hash Detected",
        "key": "pass_the_hash",
        "severity": "CRITICAL",
        "lateral": True,
        # NTLM logon (type 3) from a network source with blank password in message
        "event_ids": {"4624"},
        "conditions": lambda row, msg, logon_type, ip: (
            logon_type == "3"
            and ip not in ("", "—", "-", "::1", "127.0.0.1")
            and re.search(r"NTLM\b", msg, re.I)
            and re.search(r"Package\s*:\s*NTLM", msg, re.I)
            # Blank LM hash indicator: "NtLmSsp " package with no kerb
            and not re.search(r"Kerberos", msg, re.I)
        ),
        "description": "Network logon via NTLM from remote IP — possible Pass-the-Hash.",
    },
    {
        "id": "WIN-LAT-002",
        "name": "⚠ PsExec / Remote Service Execution",
        "key": "psexec",
        "severity": "CRITICAL",
        "lateral": True,
        "event_ids": {"7045", "4697"},
        "conditions": lambda row, msg, logon_type, ip: (
            re.search(r"PSEXESVC|psexec|\\ADMIN\$|RemCom", msg, re.I)
        ),
        "description": "PsExec service or remote execution artifact detected.",
    },
    {
        "id": "WIN-LAT-003",
        "name": "⚠ WMI Remote Execution",
        "key": "wmi_execution",
        "severity": "HIGH",
        "lateral": True,
        "event_ids": {"4624", "4648"},
        "conditions": lambda row, msg, logon_type, ip: (
            re.search(r"WMI|WMIC|winmgmt|wbem", msg, re.I)
            and logon_type in ("3", "")
            and ip not in ("", "—", "-", "::1", "127.0.0.1")
        ),
        "description": "WMI-based remote process execution detected.",
    },
    {
        "id": "WIN-LAT-004",
        "name": "⚠ Admin Share Access (SMB Lateral Movement)",
        "key": "smb_lateral",
        "severity": "HIGH",
        "lateral": True,
        "event_ids": {"5140", "5145"},
        "conditions": lambda row, msg, logon_type, ip: (
            re.search(r"\\\\.*\\(ADMIN|IPC|C)\$", msg, re.I)
            and ip not in ("", "—", "-", "::1", "127.0.0.1")
        ),
        "description": "Access to administrative share from remote IP.",
    },
    {
        "id": "WIN-LAT-005",
        "name": "⚠ DCOM Remote Execution",
        "key": "dcom_execution",
        "severity": "HIGH",
        "lateral": True,
        "event_ids": {"4624"},
        "conditions": lambda row, msg, logon_type, ip: (
            logon_type == "3"
            and re.search(r"DCOM|MMC20|ShellBrowserWindow|ShellWindows", msg, re.I)
            and ip not in ("", "—", "-", "::1", "127.0.0.1")
        ),
        "description": "DCOM-based lateral movement technique detected.",
    },
    {
        "id": "WIN-LAT-006",
        "name": "⚠ Remote Scheduled Task Creation",
        "key": "scheduled_task_remote",
        "severity": "HIGH",
        "lateral": True,
        "event_ids": {"4698", "4702"},
        "conditions": lambda row, msg, logon_type, ip: True,
        "description": "Scheduled task created — possible remote execution pivot.",
    },
    {
        "id": "WIN-LAT-007",
        "name": "⚠ Token Impersonation",
        "key": "token_impersonation",
        "severity": "HIGH",
        "lateral": True,
        "event_ids": {"4624"},
        "conditions": lambda row, msg, logon_type, ip: (
            logon_type in ("9", "5")   # NewCredentials or Service logon
            and ip not in ("", "—", "-", "::1", "127.0.0.1")
        ),
        "description": "Service or NewCredentials logon type — possible token impersonation.",
    },
]

# Build a fast lookup: event_id → list of lateral rules
_WIN_LATERAL_BY_ID = defaultdict(list)
for _rule in WINDOWS_LATERAL_RULES:
    for _eid in _rule["event_ids"]:
        _WIN_LATERAL_BY_ID[_eid].append(_rule)

# ── Windows Event ID Rules ────────────────────────────────────────────────────

WINDOWS_EVENT_RULES = {
    "4625": {
        "id": "WIN-AUTH-001",
        "name": "Failed Windows Logon",
        "key":  "win_failed_logon",
        "severity": "MEDIUM",
        "track_brute": True,
    },
    "4624": {
        "id": "WIN-AUTH-002",
        "name": "Successful Windows Logon",
        "key":  "win_logon_success",
        "severity": "LOW",
        "rdp_check": True,
    },
    "4720": {
        "id": "WIN-ACCT-001",
        "name": "User Account Created",
        "key":  "win_user_created",
        "severity": "HIGH",
    },
    "4726": {
        "id": "WIN-ACCT-002",
        "name": "User Account Deleted",
        "key":  "win_user_deleted",
        "severity": "HIGH",
    },
    "4732": {
        "id": "WIN-PRIV-001",
        "name": "User Added to Privileged Group",
        "key":  "win_priv_escalation",
        "severity": "HIGH",
    },
    "4648": {
        "id": "WIN-PRIV-002",
        "name": "Logon with Explicit Credentials",
        "key":  "win_priv_escalation",
        "severity": "MEDIUM",
    },
    "1102": {
        "id": "WIN-EVASION-001",
        "name": "⚠ Audit Log Cleared",
        "key":  "win_audit_cleared",
        "severity": "HIGH",
    },
    "7045": {
        "id": "WIN-SVC-001",
        "name": "New Service Installed",
        "key":  "win_service_install",
        "severity": "HIGH",
    },
    "4697": {
        "id": "WIN-SVC-002",
        "name": "Service Installed in System",
        "key":  "win_service_install",
        "severity": "HIGH",
    },
    "5140": {
        "id": "WIN-SMB-001",
        "name": "Network Share Accessed",
        "key":  "admin_share_access",
        "severity": "MEDIUM",
    },
    "5145": {
        "id": "WIN-SMB-002",
        "name": "Network Share Object Checked",
        "key":  "admin_share_access",
        "severity": "MEDIUM",
    },
    "4698": {
        "id": "WIN-TASK-001",
        "name": "Scheduled Task Created",
        "key":  "scheduled_task_remote",
        "severity": "HIGH",
    },
    "4702": {
        "id": "WIN-TASK-002",
        "name": "Scheduled Task Updated",
        "key":  "scheduled_task_remote",
        "severity": "HIGH",
    },
    "4776": {
        "id": "WIN-AUTH-003",
        "name": "Failed Credential Validation (NTLM)",
        "key":  "win_failed_logon",
        "severity": "MEDIUM",
        "track_brute": True,
    },
}

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW    = 60  # seconds
INCIDENT_WINDOW       = 600 # seconds
LATERAL_TIME_WINDOW   = 300 # seconds

CONFIG = {
    "known_good_ips": set(),
    "admin_users": set(),
    "watchlist_users": set(),
    "expected_admin_activity": [],
}

# ── Helpers ───────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def colorize(text, severity):
    if not COLOR:
        return text
    colors = {
        "CRITICAL": Fore.MAGENTA,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.CYAN,
    }
    return colors.get(severity, "") + text + Style.RESET_ALL

def require_int(config, key, current):
    if key not in config:
        return current
    if isinstance(config[key], bool) or not isinstance(config[key], int):
        raise ValueError(f"{key} must be an integer")
    if config[key] <= 0:
        raise ValueError(f"{key} must be greater than 0")
    return config[key]

def require_string_list(config, key):
    value = config.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a list of strings")
    return value

def validate_expected_admin_activity(config):
    entries = config.get("expected_admin_activity", [])
    if not isinstance(entries, list):
        raise ValueError("expected_admin_activity must be a list")
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"expected_admin_activity[{idx}] must be an object")
        for key in ("user", "source_ip", "host"):
            if key in entry and not isinstance(entry[key], str):
                raise ValueError(f"expected_admin_activity[{idx}].{key} must be a string")
        allowed = entry.get("allowed_commands", [])
        if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
            raise ValueError(f"expected_admin_activity[{idx}].allowed_commands must be a list of strings")
    return entries

def load_config(path):
    global BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, INCIDENT_WINDOW, LATERAL_TIME_WINDOW
    if not path:
        return

    with open(path, "r", encoding="utf-8") as f:
        config = json.load(f)

    if not isinstance(config, dict):
        raise ValueError("config file must contain a JSON object")

    BRUTE_FORCE_THRESHOLD = require_int(config, "brute_force_threshold", BRUTE_FORCE_THRESHOLD)
    BRUTE_FORCE_WINDOW = require_int(config, "brute_force_window_seconds", BRUTE_FORCE_WINDOW)
    INCIDENT_WINDOW = require_int(config, "incident_window_seconds", INCIDENT_WINDOW)
    LATERAL_TIME_WINDOW = require_int(config, "lateral_ssh_window_seconds", LATERAL_TIME_WINDOW)
    CONFIG["known_good_ips"] = set(require_string_list(config, "known_good_ips"))
    CONFIG["admin_users"] = set(require_string_list(config, "admin_users"))
    CONFIG["watchlist_users"] = set(require_string_list(config, "watchlist_users"))
    CONFIG["expected_admin_activity"] = validate_expected_admin_activity(config)

def iter_detection_rules():
    for rule in LINUX_RULES:
        mitre_id, mitre_name = MITRE[rule["key"]]
        yield {
            "id": rule["id"],
            "name": rule["name"].lstrip("⚠ ").strip(),
            "source": "Linux auth.log",
            "event_id": "—",
            "mitre_id": mitre_id,
            "mitre_name": mitre_name,
            "severity": rule["severity"],
        }
    yield {
        "id": "LINUX-SSH-003",
        "name": "Brute Force Detected",
        "source": "Linux auth.log",
        "event_id": "—",
        "mitre_id": MITRE["brute_force"][0],
        "mitre_name": MITRE["brute_force"][1],
        "severity": "HIGH",
    }
    yield {
        "id": "LINUX-LAT-003",
        "name": "Lateral Movement - Multi-Source SSH",
        "source": "Linux auth.log",
        "event_id": "—",
        "mitre_id": MITRE["linux_lateral_ssh"][0],
        "mitre_name": MITRE["linux_lateral_ssh"][1],
        "severity": "HIGH",
    }
    for event_id, rule in WINDOWS_EVENT_RULES.items():
        mitre_id, mitre_name = MITRE[rule["key"]]
        yield {
            "id": rule["id"],
            "name": rule["name"].lstrip("⚠ ").strip(),
            "source": "Windows Event Log CSV",
            "event_id": event_id,
            "mitre_id": mitre_id,
            "mitre_name": mitre_name,
            "severity": rule["severity"],
        }
    yield {
        "id": "WIN-AUTH-004",
        "name": "RDP Logon (Remote Desktop)",
        "source": "Windows Event Log CSV",
        "event_id": "4624",
        "mitre_id": MITRE["win_rdp_logon"][0],
        "mitre_name": MITRE["win_rdp_logon"][1],
        "severity": "HIGH",
    }
    yield {
        "id": "WIN-AUTH-005",
        "name": "Brute Force Detected (Windows)",
        "source": "Windows Event Log CSV",
        "event_id": "4625/4776",
        "mitre_id": MITRE["brute_force"][0],
        "mitre_name": MITRE["brute_force"][1],
        "severity": "HIGH",
    }
    for rule in WINDOWS_LATERAL_RULES:
        mitre_id, mitre_name = MITRE[rule["key"]]
        yield {
            "id": rule["id"],
            "name": rule["name"].lstrip("⚠ ").strip(),
            "source": "Windows Event Log CSV",
            "event_id": "/".join(sorted(rule["event_ids"])),
            "mitre_id": mitre_id,
            "mitre_name": mitre_name,
            "severity": rule["severity"],
        }

def print_rules():
    rules = sorted(iter_detection_rules(), key=lambda item: item["id"])
    print("\nDetection Rules")
    print("-" * 112)
    print(f"{'Rule ID':<16} {'Source':<24} {'Event':<10} {'Severity':<9} {'MITRE':<11} Detection")
    print("-" * 112)
    for rule in rules:
        print(
            f"{rule['id']:<16} {rule['source']:<24} {rule['event_id']:<10} "
            f"{rule['severity']:<9} {rule['mitre_id']:<11} {rule['name']}"
        )
    print()

def triage_context(alert):
    user = alert.get("user", "")
    ips = [ip.strip() for ip in str(alert.get("ip", "")).split(",")]
    return {
        "known_good_ip": any(ip in CONFIG["known_good_ips"] for ip in ips),
        "admin_user": user in CONFIG["admin_users"],
        "watchlist_user": user in CONFIG["watchlist_users"],
        "expected_admin_activity": expected_admin_activity(alert),
    }

def expected_admin_activity(alert):
    user = alert.get("user", "")
    ips = [ip.strip() for ip in str(alert.get("ip", "")).split(",")]
    cmd = str(alert.get("cmd", ""))
    host = alert.get("host", "")
    for item in CONFIG["expected_admin_activity"]:
        if item.get("user") and item["user"] != user:
            continue
        meaningful_ips = [ip for ip in ips if ip not in ("", "—", "unknown")]
        if item.get("source_ip") and meaningful_ips and item["source_ip"] not in meaningful_ips:
            continue
        if item.get("host") and item["host"] != host:
            continue
        allowed_commands = item.get("allowed_commands", [])
        if allowed_commands and not any(allowed in cmd for allowed in allowed_commands):
            continue
        return True
    return False

def parse_linux_host(line):
    m = re.search(r"^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?P<host>\S+)", line)
    return m.group("host") if m else "unknown"

def parse_windows_host(row, message):
    for field in ("Computer", "MachineName", "Host", "Hostname"):
        value = (row.get(field) or "").strip().strip('"')
        if value:
            return value
    for pattern in [
        r"Computer:\s+(\S+)",
        r"Workstation Name:\s+(\S+)",
        r"Workstation:\s+(\S+)",
    ]:
        m = re.search(pattern, message, re.I)
        if m and m.group(1) not in ("-", "—"):
            return m.group(1)
    return "unknown"

def extract_windows_field(message, labels):
    label_pattern = "|".join(re.escape(label) for label in labels)
    boundary = (
        r"Account Name|TargetUserName|SubjectUserName|Workstation Name|Source Network Address|"
        r"Logon Type|Authentication Package|Process Name|Service Name|Share Name|Computer"
    )
    m = re.search(
        rf"(?:{label_pattern})\s*:\s*(?P<value>.*?)(?=\s+(?:{boundary})\s*:|$)",
        message,
        re.I,
    )
    if not m:
        return ""
    value = m.group("value").strip().strip('"')
    return "" if value in ("", "-", "—") else value

def parse_windows_message(message):
    target_user = extract_windows_field(message, ["TargetUserName"])
    account_user = extract_windows_field(message, ["Account Name"])
    subject_user = extract_windows_field(message, ["SubjectUserName"])
    candidates = [target_user, account_user, subject_user]
    user = next((item for item in candidates if item and "$" not in item), "unknown")

    ip = extract_windows_field(message, ["Source Network Address"]) or "—"
    logon_type = extract_windows_field(message, ["Logon Type"]) or "—"
    details = {
        "target_user": target_user or user,
        "subject_user": subject_user or "—",
        "workstation": extract_windows_field(message, ["Workstation Name"]) or "—",
        "source_ip": ip,
        "logon_type": logon_type,
        "auth_package": extract_windows_field(message, ["Authentication Package"]) or "—",
        "process_name": extract_windows_field(message, ["Process Name"]) or "—",
    }
    return user, ip, logon_type, details

def top_entities(alerts, field, limit=5):
    counts = defaultdict(int)
    for alert in alerts:
        value = alert.get(field, "")
        if not value or value in ("—", "unknown", "multiple"):
            continue
        for part in str(value).split(","):
            part = part.strip()
            if part and part not in ("—", "unknown", "multiple"):
                counts[part] += 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]

def analyst_verdict(incident):
    if any(triage_context(a)["expected_admin_activity"] for a in incident["alerts"]) and incident["risk_score"] < 80:
        return "Likely False Positive", "Medium", "Activity matches expected admin context from the config."
    if incident["risk_score"] >= 85 or incident["severity"] == "CRITICAL":
        return "Likely True Positive", "High", "High-risk chained behavior or critical activity was observed."
    if incident["risk_score"] >= 50 or incident["lateral"]:
        return "Needs Review", "Medium", "Suspicious behavior is present, but analyst validation is required."
    return "Informational", "Low", "Low-risk activity with limited malicious indicators."

def timeline_lines(incidents):
    rows = []
    for incident in incidents:
        for alert in incident["alerts"]:
            rows.append((alert_time(alert) or datetime.max, incident["id"], alert))
    rows.sort(key=lambda item: item[0])
    return [
        f"{alert['timestamp']} | {incident_id} | {alert.get('detection_id', 'NO-ID')} | "
        f"{alert['severity']} | {alert['name']} | user={alert['user']} | ip={alert['ip']} | host={alert.get('host', 'unknown')}"
        for _, incident_id, alert in rows
    ]

def mitre_summary(alerts):
    summary = defaultdict(lambda: {"name": "", "count": 0, "severities": defaultdict(int)})
    for alert in alerts:
        mitre_id = alert.get("mitre_id", "unknown")
        summary[mitre_id]["name"] = alert.get("mitre_name", "")
        summary[mitre_id]["count"] += 1
        summary[mitre_id]["severities"][alert.get("severity", "UNKNOWN")] += 1
    return [
        {
            "mitre_id": mitre_id,
            "mitre_name": data["name"],
            "count": data["count"],
            "severities": dict(data["severities"]),
        }
        for mitre_id, data in sorted(summary.items(), key=lambda item: (-item[1]["count"], item[0]))
    ]

def parse_timestamp(line):
    for fmt, pattern in [
        ("%Y-%m-%d %H:%M:%S", r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
        ("%m/%d/%Y %H:%M:%S", r"(\d{1,2}/\d{1,2}/\d{4} \d{2}:\d{2}:\d{2})"),
        ("%m/%d/%Y %I:%M:%S %p", r"(\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} [APM]{2})"),
    ]:
        m = re.search(pattern, line)
        if m:
            try:
                return datetime.strptime(m.group(1), fmt)
            except ValueError:
                pass
    m = re.search(r"([A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            return datetime.strptime(m.group(1), "%b %d %H:%M:%S").replace(year=datetime.now().year)
        except ValueError:
            pass
    return None

def alert_time(alert):
    ts = alert.get("timestamp", "")
    if ts == "unknown":
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            pass
    return parse_timestamp(ts)

def severity_rank(severity):
    return SEVERITY_ORDER.get(severity, 9)

def highest_severity(alerts):
    return min((a["severity"] for a in alerts), key=severity_rank, default="LOW")

def incident_key(alert):
    user = alert.get("user") or "unknown"
    ip = alert.get("ip") or "—"
    if user not in ("unknown", "multiple", "—"):
        return f"user:{user}"
    if ip != "—":
        return f"ip:{ip.split(',')[0].strip()}"
    return "general"

def playbook_steps(alerts):
    names = " ".join(a.get("name", "").lower() for a in alerts)
    steps = []

    if "brute force" in names or "failed" in names:
        steps.extend([
            "Check whether the same source IP later achieved a successful login.",
            "Review the targeted account for lockouts, MFA prompts, password changes, and recent privilege use.",
            "Look up the source IP in firewall, VPN, EDR, and threat intelligence logs.",
        ])
    if "accepted ssh" in names or "successful" in names or "rdp" in names:
        steps.extend([
            "Validate whether the login source, time, and account are expected for this user.",
            "Review commands, process creation, and session activity immediately after authentication.",
        ])
    if "sudo" in names or "privileged" in names or "root" in names:
        steps.extend([
            "Review privileged commands and confirm they match an approved admin change.",
            "Check for persistence, new accounts, modified SSH keys, and unusual service changes.",
        ])
    if "new user" in names or "account created" in names:
        steps.extend([
            "Confirm the account owner, ticket/change request, group membership, and UID/GID values.",
            "Disable or contain the account if ownership cannot be validated quickly.",
        ])
    if any(a.get("lateral") for a in alerts):
        steps.extend([
            "Build a host-to-host timeline to determine the original entry point and next pivot.",
            "Check destination hosts for matching logons, admin share access, service creation, WMI, or scheduled tasks.",
        ])
    if "pass-the-hash" in names or "psexec" in names or "wmi" in names or "dcom" in names:
        steps.extend([
            "Collect endpoint telemetry for remote process execution and credential material exposure.",
            "Reset or rotate credentials for affected privileged accounts after containment.",
        ])
    if "audit log cleared" in names:
        steps.append("Treat log clearing as potential defense evasion and preserve remaining endpoint, SIEM, and EDR evidence.")

    if not steps:
        steps.extend([
            "Validate whether the activity is expected for the account, host, source IP, and time window.",
            "Search nearby events for authentication, privilege, persistence, and lateral movement indicators.",
        ])

    deduped = []
    for step in steps:
        if step not in deduped:
            deduped.append(step)
    return deduped[:6]

def containment_steps(alerts):
    names = " ".join(a.get("name", "").lower() for a in alerts)
    steps = []
    if "brute force" in names or "failed" in names:
        steps.append("Block or rate-limit the source IP if activity is unauthorized and still active.")
        steps.append("Reset credentials or enforce MFA for targeted accounts if compromise is suspected.")
    if "successful" in names or "accepted ssh" in names or "rdp" in names:
        steps.append("Temporarily disable or isolate the affected account if the login cannot be validated.")
    if any(a.get("lateral") for a in alerts):
        steps.append("Isolate affected hosts from peer systems while confirming the pivot path.")
    if "new user" in names or "account created" in names:
        steps.append("Disable newly created accounts until ownership and change approval are confirmed.")
    if "audit log cleared" in names:
        steps.append("Preserve remaining SIEM, EDR, firewall, and endpoint evidence before normal cleanup.")
    if not steps:
        steps.append("Monitor the involved user, host, and source IP while validating business context.")
    return steps[:5]

def followup_queries(alerts):
    users = sorted({a.get("user") for a in alerts if a.get("user") not in ("", "unknown", "multiple", "—")})
    ips = sorted({ip.strip() for a in alerts for ip in str(a.get("ip", "")).split(",") if ip.strip() not in ("", "—")})
    hosts = sorted({a.get("host") for a in alerts if a.get("host") not in ("", "unknown", "—")})
    user_filter = " OR ".join(f'user="{user}"' for user in users) or 'user="unknown"'
    ip_filter = " OR ".join(f'source_ip="{ip}"' for ip in ips) or 'source_ip="unknown"'
    host_filter = " OR ".join(f'host="{host}"' for host in hosts) or 'host="unknown"'
    return [
        f"Search authentication events for ({user_filter}) during the incident window.",
        f"Search network, VPN, firewall, and EDR telemetry for ({ip_filter}).",
        f"Search process, service, scheduled task, and account changes for ({host_filter}).",
    ]

def false_positive_notes(alerts):
    notes = [
        "Confirm whether the activity matches an approved change window, helpdesk ticket, admin task, or vulnerability scan.",
        "Validate whether the source IP belongs to VPN, jump box, scanner, backup, or management infrastructure.",
    ]
    if any(triage_context(a)["expected_admin_activity"] for a in alerts):
        notes.insert(0, "The config marks part of this activity as expected admin behavior.")
    if any(triage_context(a)["known_good_ip"] for a in alerts):
        notes.insert(0, "At least one source IP is configured as known-good, but the sequence still needs validation.")
    return notes[:4]

def evidence_summary(alerts):
    evidence = []
    names = " ".join(a.get("name", "").lower() for a in alerts)
    users = sorted({a.get("user") for a in alerts if a.get("user") not in ("", "unknown", "multiple", "—")})
    ips = sorted({ip.strip() for a in alerts for ip in str(a.get("ip", "")).split(",") if ip.strip() not in ("", "—")})

    for alert in alerts:
        name = alert.get("name", "")
        if "Brute Force" in name:
            evidence.append(alert.get("description") or alert.get("raw"))
        elif "Accepted SSH" in name or "Successful" in name or "RDP" in name:
            evidence.append(f"Successful authentication for {alert.get('user')} from {alert.get('ip')}")
        elif "sudo" in name:
            cmd = alert.get("cmd")
            if cmd and cmd != "—":
                evidence.append(f"Privilege activity by {alert.get('user')}: {cmd}")
            else:
                evidence.append(f"Privilege-related sudo event for {alert.get('user')}")
        elif "New User" in name or "Account Created" in name:
            evidence.append(f"Account creation observed for {alert.get('user')}")
        elif alert.get("lateral"):
            evidence.append(alert.get("description") or name)

    if users:
        evidence.append(f"Observed user(s): {', '.join(users)}")
    if ips:
        evidence.append(f"Observed source IP(s): {', '.join(ips)}")
    if any(triage_context(a)["known_good_ip"] for a in alerts):
        evidence.append("At least one source IP is listed as known-good in the config.")
    if any(triage_context(a)["expected_admin_activity"] for a in alerts):
        evidence.append("Activity matches an expected admin pattern from the config.")
    if any(triage_context(a)["watchlist_user"] for a in alerts):
        evidence.append("At least one involved account is on the watchlist.")
    if "audit log cleared" in names:
        evidence.append("Audit log clearing was observed, which may indicate defense evasion.")

    deduped = []
    for item in evidence:
        if item and item not in deduped:
            deduped.append(item)
    return deduped[:6]

def risk_score(alerts):
    score = 0
    reasons = []
    names = " ".join(a.get("name", "").lower() for a in alerts)

    weights = {
        "CRITICAL": 35,
        "HIGH": 22,
        "MEDIUM": 10,
        "LOW": 3,
    }
    for severity in {a.get("severity") for a in alerts}:
        if severity in weights:
            score += weights[severity]
            reasons.append(f"+{weights[severity]} highest {severity.lower()} activity present")

    if "brute force" in names:
        score += 25
        reasons.append("+25 brute force pattern")
    if "brute force" in names and ("accepted" in names or "successful" in names):
        score += 30
        reasons.append("+30 successful login after authentication failures")
    if "root" in names or "sudo" in names or "privileged" in names:
        score += 20
        reasons.append("+20 privilege or root activity")
    if "new user" in names or "account created" in names:
        score += 25
        reasons.append("+25 account creation")
    if any(a.get("lateral") for a in alerts):
        score += 25
        reasons.append("+25 lateral movement indicator")
    if any(triage_context(a)["watchlist_user"] for a in alerts):
        score += 15
        reasons.append("+15 watchlisted account involved")
    if any(triage_context(a)["known_good_ip"] for a in alerts):
        score -= 10
        reasons.append("-10 known-good source IP present")
    if any(triage_context(a)["expected_admin_activity"] for a in alerts):
        score -= 25
        reasons.append("-25 expected admin activity match")

    return max(0, min(100, score)), reasons[:6]

def incident_title(alerts):
    names = " ".join(a.get("name", "").lower() for a in alerts)
    if "brute force" in names and ("accepted" in names or "successful" in names):
        return "Possible Compromise After Brute Force"
    if any(a.get("lateral") for a in alerts):
        return "Possible Lateral Movement"
    if "new user" in names or "account created" in names:
        return "Suspicious Account Management"
    if "sudo" in names or "root" in names or "privileged" in names:
        return "Privilege Escalation Review"
    if "brute force" in names or "failed" in names:
        return "Authentication Attack Review"
    return "Security Event Review"

def build_incidents(alerts):
    dated_alerts = []
    for alert in alerts:
        ts = alert_time(alert)
        if ts:
            dated_alerts.append((ts, alert))

    dated_alerts.sort(key=lambda item: item[0])
    groups = []
    for ts, alert in dated_alerts:
        key = incident_key(alert)
        matched = None
        for group in groups:
            related_user = alert.get("user") in group["users"] and alert.get("user") not in ("unknown", "multiple", "—")
            related_ip = alert.get("ip") in group["ips"] and alert.get("ip") != "—"
            close = (ts - group["last_seen"]).total_seconds() <= INCIDENT_WINDOW
            if close and (group["key"] == key or related_user or related_ip):
                matched = group
                break
        if not matched:
            matched = {
                "key": key,
                "alerts": [],
                "users": set(),
                "ips": set(),
                "hosts": set(),
                "first_seen": ts,
                "last_seen": ts,
            }
            groups.append(matched)

        matched["alerts"].append(alert)
        matched["first_seen"] = min(matched["first_seen"], ts)
        matched["last_seen"] = max(matched["last_seen"], ts)
        if alert.get("user") not in ("", "unknown", "multiple", "—"):
            matched["users"].add(alert["user"])
        if alert.get("ip") not in ("", "—"):
            for ip in str(alert["ip"]).split(","):
                matched["ips"].add(ip.strip())
        if alert.get("host") not in ("", "unknown", "—"):
            matched["hosts"].add(alert["host"])

    incidents = []
    for idx, group in enumerate(groups, start=1):
        grouped_alerts = sorted(group["alerts"], key=lambda a: alert_time(a) or datetime.max)
        incidents.append({
            "id": f"INC-{idx:03d}",
            "title": incident_title(grouped_alerts),
            "severity": highest_severity(grouped_alerts),
            "first_seen": group["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": group["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
            "users": sorted(group["users"]) or ["unknown"],
            "ips": sorted(group["ips"]) or ["—"],
            "hosts": sorted(group["hosts"]) or ["unknown"],
            "alert_count": len(grouped_alerts),
            "lateral": any(a.get("lateral") for a in grouped_alerts),
            "alerts": grouped_alerts,
            "evidence": evidence_summary(grouped_alerts),
            "playbook": playbook_steps(grouped_alerts),
            "containment": containment_steps(grouped_alerts),
            "followup_queries": followup_queries(grouped_alerts),
            "false_positive_notes": false_positive_notes(grouped_alerts),
        })

    for incident in incidents:
        incident["risk_score"], incident["risk_reasons"] = risk_score(incident["alerts"])
        incident["verdict"], incident["confidence"], incident["verdict_reason"] = analyst_verdict(incident)

    incidents.sort(key=lambda i: (severity_rank(i["severity"]), i["first_seen"]))
    return incidents

def detect_format(filepath):
    with open(filepath, "r", errors="replace") as f:
        first_line = f.readline().lower()
    if "eventid" in first_line or "timecreated" in first_line or "timegenerated" in first_line:
        return "windows"
    return "linux"

# ── Windows CSV Parser ────────────────────────────────────────────────────────

def analyze_windows(filepath, severity_filter=None):
    alerts = []
    failed_by_ip = defaultdict(list)
    line_count   = 0

    with open(filepath, "r", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [h.strip().strip('"') for h in (reader.fieldnames or [])]

        for row in reader:
            line_count += 1
            event_id  = (row.get("EventID") or row.get("Id") or "").strip().strip('"')
            time_raw  = (row.get("TimeGenerated") or row.get("TimeCreated") or "").strip().strip('"')
            message   = (row.get("Message") or "").strip().strip('"')

            ts = parse_timestamp(time_raw) or parse_timestamp(message)
            user, ip, logon_type, win_fields = parse_windows_message(message)
            host = parse_windows_host(row, message)
            cmd_parts = [f"EventID:{event_id}", f"LogonType:{logon_type}"]
            if win_fields["auth_package"] != "—":
                cmd_parts.append(f"AuthPackage:{win_fields['auth_package']}")
            if win_fields["process_name"] != "—":
                cmd_parts.append(f"Process:{win_fields['process_name']}")
            cmd = "  ".join(cmd_parts)

            # ── Lateral movement rules (checked first, higher priority) ──────
            for lat_rule in _WIN_LATERAL_BY_ID.get(event_id, []):
                try:
                    matched = lat_rule["conditions"](row, message, logon_type, ip)
                except Exception:
                    matched = False
                if matched:
                    mitre_id, mitre_name = MITRE[lat_rule["key"]]
                    alerts.append({
                        "timestamp":   ts.strftime("%Y-%m-%d %H:%M:%S") if ts else time_raw,
                        "detection_id": lat_rule["id"],
                        "severity":    lat_rule["severity"],
                        "name":        lat_rule["name"],
                        "user":        user,
                        "ip":          ip,
                        "host":        host,
                        "cmd":         cmd,
                        "mitre_id":    mitre_id,
                        "mitre_name":  mitre_name,
                        "description": lat_rule.get("description", ""),
                        "lateral":     True,
                        "windows_fields": win_fields,
                        "raw":         message[:120],
                    })

            # ── Standard event rules ──────────────────────────────────────────
            if event_id not in WINDOWS_EVENT_RULES:
                continue

            rule = WINDOWS_EVENT_RULES[event_id]
            mitre_id, mitre_name = MITRE[rule["key"]]
            severity = rule["severity"]

            if rule.get("rdp_check") and logon_type == "10":
                severity  = "HIGH"
                name      = "RDP Logon (Remote Desktop)"
                mitre_id, mitre_name = MITRE["win_rdp_logon"]
                detection_id = "WIN-AUTH-004"
            else:
                name = rule["name"]
                detection_id = rule["id"]

            if rule.get("track_brute") and ip != "—" and ts:
                failed_by_ip[ip].append(ts)

            alerts.append({
                "timestamp":   ts.strftime("%Y-%m-%d %H:%M:%S") if ts else time_raw,
                "detection_id": detection_id,
                "severity":    severity,
                "name":        name,
                "user":        user,
                "ip":          ip,
                "host":        host,
                "cmd":         cmd,
                "mitre_id":    mitre_id,
                "mitre_name":  mitre_name,
                "description": "",
                "lateral":     False,
                "windows_fields": win_fields,
                "raw":         message[:120],
            })

    # Brute force correlation
    for ip, timestamps in failed_by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps) - BRUTE_FORCE_THRESHOLD + 1):
            window = timestamps[i: i + BRUTE_FORCE_THRESHOLD]
            delta  = (window[-1] - window[0]).total_seconds()
            if delta <= BRUTE_FORCE_WINDOW:
                mitre_id, mitre_name = MITRE["brute_force"]
                alerts.append({
                    "timestamp":   window[0].strftime("%Y-%m-%d %H:%M:%S"),
                    "detection_id": "WIN-AUTH-005",
                    "severity":    "HIGH",
                    "name":        "⚠  Brute Force Detected (Windows)",
                    "user":        "multiple",
                    "ip":          ip,
                    "host":        "unknown",
                    "cmd":         "EventID:4625",
                    "mitre_id":    mitre_id,
                    "mitre_name":  mitre_name,
                    "description": f"{BRUTE_FORCE_THRESHOLD} failed logons within {int(delta)}s",
                    "lateral":     False,
                    "raw":         f"[CORRELATED] {BRUTE_FORCE_THRESHOLD} failed logons from {ip} within {int(delta)}s",
                })
                break

    if severity_filter:
        f = severity_filter.upper()
        alerts = [a for a in alerts if a["severity"] == f]

    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 9))
    return alerts, line_count

# ── Linux/macOS Parser ────────────────────────────────────────────────────────

def analyze_linux(filepath, severity_filter=None):
    alerts = []
    failed_by_ip = defaultdict(list)
    ssh_sessions  = defaultdict(list)   # user → [(ts, ip)] for lateral detection
    line_count   = 0

    with open(filepath, "r", errors="replace") as f:
        lines = f.readlines()

    for line in lines:
        line_count += 1
        ts = parse_timestamp(line)
        host = parse_linux_host(line)

        for rule in LINUX_RULES:
            m = rule["pattern"].search(line)
            if not m:
                continue
            groups   = m.groupdict()
            user     = groups.get("user") or ("root" if rule["key"] == "root_login" else "unknown")
            ip       = groups.get("ip") or "—"
            cmd      = groups.get("cmd") or "—"
            mitre_id, mitre_name = MITRE[rule["key"]]

            if rule["key"] == "ssh_failed" and ip != "—" and ts:
                failed_by_ip[ip].append(ts)

            # Track SSH acceptances per user for lateral-movement chaining
            if rule["key"] == "ssh_accepted" and ip != "—" and ts:
                ssh_sessions[user].append((ts, ip))

            alerts.append({
                "timestamp":   ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown",
                "detection_id": rule["id"],
                "severity":    rule["severity"],
                "name":        rule["name"],
                "user":        user,
                "ip":          ip,
                "host":        host,
                "cmd":         cmd,
                "mitre_id":    mitre_id,
                "mitre_name":  mitre_name,
                "description": "",
                "lateral":     rule.get("lateral", False),
                "raw":         line.strip(),
            })

    # ── Linux lateral movement: same user logging in from multiple IPs quickly ─
    LATERAL_IP_THRESHOLD  = 2   # ≥2 different source IPs
    for user, sessions in ssh_sessions.items():
        sessions.sort(key=lambda x: x[0])
        for i in range(len(sessions)):
            window_sessions = [
                s for s in sessions[i:]
                if (s[0] - sessions[i][0]).total_seconds() <= LATERAL_TIME_WINDOW
            ]
            unique_ips = {s[1] for s in window_sessions}
            if len(unique_ips) >= LATERAL_IP_THRESHOLD:
                mitre_id, mitre_name = MITRE["linux_lateral_ssh"]
                alerts.append({
                    "timestamp":   sessions[i][0].strftime("%Y-%m-%d %H:%M:%S"),
                    "detection_id": "LINUX-LAT-003",
                    "severity":    "HIGH",
                    "name":        "⚠ Lateral Movement – Multi-Source SSH",
                    "user":        user,
                    "ip":          ", ".join(sorted(unique_ips)),
                    "host":        "unknown",
                    "cmd":         "—",
                    "mitre_id":    mitre_id,
                    "mitre_name":  mitre_name,
                    "description": f"User '{user}' authenticated from {len(unique_ips)} different IPs within {LATERAL_TIME_WINDOW}s",
                    "lateral":     True,
                    "raw":         f"[CORRELATED] SSH from: {', '.join(sorted(unique_ips))}",
                })
                break

    # Brute force correlation
    for ip, timestamps in failed_by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps) - BRUTE_FORCE_THRESHOLD + 1):
            window = timestamps[i: i + BRUTE_FORCE_THRESHOLD]
            delta  = (window[-1] - window[0]).total_seconds()
            if delta <= BRUTE_FORCE_WINDOW:
                mitre_id, mitre_name = MITRE["brute_force"]
                alerts.append({
                    "timestamp":   window[0].strftime("%Y-%m-%d %H:%M:%S"),
                    "detection_id": "LINUX-SSH-003",
                    "severity":    "HIGH",
                    "name":        "⚠  Brute Force Detected",
                    "user":        "multiple",
                    "ip":          ip,
                    "host":        "unknown",
                    "cmd":         "—",
                    "mitre_id":    mitre_id,
                    "mitre_name":  mitre_name,
                    "description": f"{BRUTE_FORCE_THRESHOLD} failed logins within {int(delta)}s",
                    "lateral":     False,
                    "raw":         f"[CORRELATED] {BRUTE_FORCE_THRESHOLD} failed logins from {ip} within {int(delta)}s",
                })
                break

    if severity_filter:
        f = severity_filter.upper()
        alerts = [a for a in alerts if a["severity"] == f]

    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 9))
    return alerts, line_count

# ── Dispatcher ────────────────────────────────────────────────────────────────

def analyze(filepath, severity_filter=None):
    try:
        fmt = detect_format(filepath)
    except FileNotFoundError:
        print(f"\n[ERROR] File not found: {filepath}")
        return None

    print(f"\n  [*] Detected format: {'Windows Event Log CSV' if fmt == 'windows' else 'Linux/macOS syslog'}")

    if fmt == "windows":
        return analyze_windows(filepath, severity_filter)
    else:
        return analyze_linux(filepath, severity_filter)

# ── Terminal Output ───────────────────────────────────────────────────────────

def print_report(alerts, incidents, line_count, filepath):
    counts = defaultdict(int)
    for a in alerts:
        counts[a["severity"]] += 1
    lateral_count = sum(1 for a in alerts if a.get("lateral"))

    print("\n" + "═" * 70)
    print("  SOC LOG ANALYZER — TRIAGE REPORT")
    print("═" * 70)
    print(f"  File          : {filepath}")
    print(f"  Lines         : {line_count:,}")
    print(f"  Alerts        : {len(alerts)}  "
          f"[CRITICAL: {counts['CRITICAL']}  HIGH: {counts['HIGH']}  "
          f"MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}]")
    print(f"  Incidents     : {len(incidents)}")
    if lateral_count:
        print(colorize(f"  Lateral Move  : {lateral_count} indicator(s) detected", "CRITICAL"))
    print("═" * 70 + "\n")

    if not alerts:
        print("  No alerts matched. Try running without --severity to see all findings.\n")
        return

    print("  INCIDENT CASES")
    print("  " + "─" * 66)
    for incident in incidents:
        sev_label = f"[{incident['severity']:<8}]"
        lateral = "  lateral movement" if incident["lateral"] else ""
        print(f"  {incident['id']} {colorize(sev_label, incident['severity'])} {incident['title']}{lateral}")
        print(f"       Window : {incident['first_seen']} → {incident['last_seen']}")
        print(f"       Users  : {', '.join(incident['users'])}")
        print(f"       IPs    : {', '.join(incident['ips'])}")
        print(f"       Hosts  : {', '.join(incident['hosts'])}")
        print(f"       Alerts : {incident['alert_count']}")
        print(f"       Risk   : {incident['risk_score']}/100")
        print(f"       Verdict: {incident['verdict']} ({incident['confidence']} confidence)")
        print(f"       Reason : {incident['verdict_reason']}")
        print("       Evidence:")
        for item in incident["evidence"]:
            print(f"         - {item}")
        print("       Timeline:")
        for a in incident["alerts"]:
            print(f"         - {a['timestamp']} [{a['severity']}] {a['name']} ({a['mitre_id']})")
        print("       Analyst playbook:")
        for step in incident["playbook"]:
            print(f"         - {step}")
        print()

    summary = mitre_summary(alerts)
    if summary:
        print("  TOP ENTITIES")
        print("  " + "─" * 66)
        for label, field in (("Users", "user"), ("Source IPs", "ip"), ("Hosts", "host")):
            top = top_entities(alerts, field)
            values = ", ".join(f"{value} ({count})" for value, count in top) if top else "none"
            print(f"  {label:<10}: {values}")
        print()

        print("  MITRE ATT&CK SUMMARY")
        print("  " + "─" * 66)
        for item in summary:
            print(f"  {item['mitre_id']:<10} {item['count']:>3}  {item['mitre_name']}")
        print()

    print("  ALERT DETAILS")
    print("  " + "─" * 66)
    for a in alerts:
        sev_label = f"[{a['severity']:<8}]"
        prefix = "  🔴 " if a.get("lateral") else "     "
        print(prefix + colorize(sev_label, a["severity"]) + f"  {a['timestamp']}  {a['name']}")
        print(f"               Rule : {a.get('detection_id', 'NO-ID')}")
        print(f"               User : {a['user']}   IP : {a['ip']}")
        print(f"               Host : {a.get('host', 'unknown')}")
        if a["cmd"] not in ("—", ""):
            print(f"               Info : {a['cmd'][:80]}")
        if a.get("description"):
            print(f"               Note : {a['description']}")
        context = triage_context(a)
        labels = []
        if context["known_good_ip"]:
            labels.append("known-good IP")
        if context["admin_user"]:
            labels.append("admin user")
        if context["watchlist_user"]:
            labels.append("watchlist user")
        if context["expected_admin_activity"]:
            labels.append("expected admin activity")
        if labels:
            print(f"               Ctx  : {', '.join(labels)}")
        print(f"               MITRE: {a['mitre_id']} – {a['mitre_name']}")
        print(f"               Raw  : {a['raw'][:100]}")
        print()

    print("═" * 70)
    print("  Tip: Run with --html report.html for a visual dashboard.")
    print("═" * 70 + "\n")

# ── HTML Dashboard ────────────────────────────────────────────────────────────

def export_html(alerts, incidents, line_count, filepath, outfile):
    counts = defaultdict(int)
    for a in alerts:
        counts[a["severity"]] += 1
    lateral_count = sum(1 for a in alerts if a.get("lateral"))
    generated_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sev_dot = {
        "CRITICAL": "#9333ea",
        "HIGH":     "#ef4444",
        "MEDIUM":   "#f59e0b",
        "LOW":      "#6b7280",
    }

    summary_html = ""
    for item in mitre_summary(alerts):
        summary_html += f"""
      <tr>
        <td><span class="mitre-id">{item['mitre_id']}</span></td>
        <td>{item['mitre_name']}</td>
        <td class="mono">{item['count']}</td>
      </tr>"""

    top_html = ""
    for label, field in (("Users", "user"), ("Source IPs", "ip"), ("Hosts", "host")):
        values = top_entities(alerts, field)
        rendered = "".join(f"<span class=\"entity-chip\">{html_lib.escape(value)} <strong>{count}</strong></span>" for value, count in values)
        top_html += f"""
    <div class="entity-card">
      <div class="entity-label">{label}</div>
      <div class="entity-list">{rendered if rendered else '<span class="muted">none</span>'}</div>
    </div>"""

    rows_html = ""
    for a in alerts:
        sev   = a["severity"]
        dot   = sev_dot.get(sev, "#6b7280")
        name  = a["name"].lstrip("⚠ ").strip()
        desc  = f'<div class="desc">{a["description"]}</div>' if a.get("description") else ""
        lat   = '<span class="lat-pill">lateral</span>' if a.get("lateral") else ""
        rows_html += f"""
      <tr data-sev="{sev}" data-lat="{'1' if a.get('lateral') else '0'}">
        <td><span class="dot" style="background:{dot}"></span></td>
        <td class="sev-cell">{sev.capitalize()}</td>
        <td class="ts">{a['timestamp']}</td>
        <td><span class="name">{name}</span>{lat}<div class="desc">{a.get('detection_id', 'NO-ID')}</div>{desc}</td>
        <td class="mono">{a['user']}</td>
        <td class="mono ip">{a['ip']}</td>
        <td class="mono">{a.get('host', 'unknown')}</td>
        <td><span class="mitre-id">{a['mitre_id']}</span><span class="mitre-name">{a['mitre_name']}</span></td>
      </tr>"""

    incidents_html = ""
    for incident in incidents:
        timeline = ""
        for alert in incident["alerts"]:
            timeline += f"""
        <li><span class="ts">{alert['timestamp']}</span> <strong>{alert['severity']}</strong> {alert['name']} <span class="mitre-id inline">{alert['mitre_id']}</span></li>"""
        playbook = ""
        for step in incident["playbook"]:
            playbook += f"<li>{step}</li>"
        evidence = ""
        for item in incident["evidence"]:
            evidence += f"<li>{item}</li>"
        reasons = ""
        for item in incident["risk_reasons"]:
            reasons += f"<li>{item}</li>"
        lateral = '<span class="lat-pill">lateral</span>' if incident["lateral"] else ""
        incidents_html += f"""
    <section class="incident">
      <div class="incident-head">
        <div>
          <div class="incident-id">{incident['id']} · {incident['severity'].capitalize()}</div>
          <h2>{incident['title']} {lateral}</h2>
        </div>
        <div class="incident-count">{incident['alert_count']} alerts · Risk {incident['risk_score']}/100</div>
      </div>
      <div class="incident-meta">
        <span>Verdict: <strong>{incident['verdict']}</strong> ({incident['confidence']})</span>
        <span>{incident['first_seen']} → {incident['last_seen']}</span>
        <span>Users: <strong>{', '.join(incident['users'])}</strong></span>
        <span>IPs: <strong>{', '.join(incident['ips'])}</strong></span>
        <span>Hosts: <strong>{', '.join(incident['hosts'])}</strong></span>
      </div>
      <div class="incident-grid">
        <div>
          <h3>Evidence</h3>
          <ul>{evidence}</ul>
        </div>
        <div>
          <h3>Risk factors</h3>
          <ul>{reasons}</ul>
        </div>
        <div>
          <h3>Timeline</h3>
          <ul>{timeline}</ul>
        </div>
        <div>
          <h3>Analyst playbook</h3>
          <ul>{playbook}</ul>
        </div>
      </div>
    </section>"""

    lateral_banner = ""
    if lateral_count:
        lateral_banner = f"""
    <div class="banner">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style="flex-shrink:0;margin-top:1px"><path d="M8 2L14 13H2L8 2Z" stroke="#b45309" stroke-width="1.5" fill="none"/><path d="M8 6v3M8 10.5v.5" stroke="#b45309" stroke-width="1.5" stroke-linecap="round"/></svg>
      <span><strong>{lateral_count} lateral movement indicator{"s" if lateral_count != 1 else ""} detected</strong> — review these alerts first.</span>
    </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Report — {filepath}</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  color: #172033;
  background: #f5f7fb;
  min-height: 100vh;
}}

.page {{ max-width: 1280px; margin: 0 auto; padding: 32px; }}

.top {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 22px;
  flex-wrap: wrap;
  gap: 16px;
  background: #ffffff;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05);
}}
h1 {{ font-size: 24px; font-weight: 700; color: #0f172a; letter-spacing: 0; }}
.meta {{ font-size: 13px; color: #64748b; margin-top: 6px; }}
.generated {{ font-size: 12px; color: #64748b; text-align: right; }}

.cards {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}}
.card {{
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 16px;
  box-shadow: 0 8px 20px rgba(15, 23, 42, 0.04);
}}
.card-num {{ font-size: 30px; font-weight: 750; line-height: 1; margin-bottom: 6px; letter-spacing: 0; }}
.card-label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }}
.card.total   .card-num {{ color: #0f172a; }}
.card.crit    .card-num {{ color: #7c3aed; }}
.card.high    .card-num {{ color: #dc2626; }}
.card.med     .card-num {{ color: #d97706; }}
.card.low     .card-num {{ color: #475569; }}
.card.lateral .card-num {{ color: #0f766e; }}

.banner {{
  display: flex;
  gap: 10px;
  align-items: flex-start;
  background: #fff7ed;
  border: 1px solid #fed7aa;
  border-radius: 8px;
  padding: 13px 15px;
  margin-bottom: 20px;
  font-size: 13px;
  color: #7c2d12;
}}
.banner strong {{ font-weight: 600; }}

.section-title {{
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #475569;
  margin: 26px 0 10px;
}}
.incident {{
  background: #fff;
  border: 1px solid #e2e8f0;
  border-left: 4px solid #0f766e;
  border-radius: 8px;
  padding: 18px;
  margin-bottom: 14px;
  box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05);
}}
.entity-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}}
.entity-card {{
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 14px;
  box-shadow: 0 10px 24px rgba(15, 23, 42, 0.04);
}}
.entity-label {{ color: #64748b; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
.entity-list {{ display: flex; flex-wrap: wrap; gap: 6px; }}
.entity-chip {{ display: inline-flex; gap: 6px; align-items: center; border: 1px solid #cbd5e1; background: #f8fafc; border-radius: 999px; padding: 3px 8px; font-size: 12px; color: #334155; }}
.entity-chip strong {{ color: #0f172a; }}
.muted {{ color: #64748b; font-size: 12px; }}
.incident-head {{
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: flex-start;
  margin-bottom: 12px;
}}
.incident-id {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }}
h2 {{ font-size: 18px; color: #0f172a; font-weight: 700; margin-top: 2px; letter-spacing: 0; }}
.incident-count {{
  font-size: 12px;
  color: #991b1b;
  background: #fee2e2;
  border: 1px solid #fecaca;
  border-radius: 999px;
  padding: 4px 10px;
  white-space: nowrap;
}}
.incident-meta {{
  display: flex;
  flex-wrap: wrap;
  gap: 8px 16px;
  font-size: 12px;
  color: #475569;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 10px 12px;
}}
.incident-grid {{
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 16px 22px;
  margin-top: 16px;
}}
h3 {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; margin-bottom: 7px; }}
ul {{ padding-left: 16px; }}
li {{ margin-bottom: 6px; color: #334155; }}
.inline {{ display: inline; margin-left: 4px; }}

.toolbar {{
  display: flex;
  gap: 6px;
  align-items: center;
  margin-bottom: 14px;
  flex-wrap: wrap;
}}
.toolbar span {{ font-size: 12px; color: #64748b; margin-right: 4px; font-weight: 600; }}
.pill {{
  font-size: 12px;
  padding: 5px 12px;
  border-radius: 20px;
  border: 1px solid #cbd5e1;
  background: #fff;
  color: #334155;
  cursor: pointer;
  transition: all 0.12s;
  font-family: inherit;
}}
.pill:hover {{ border-color: #94a3b8; background: #f8fafc; }}
.pill.on {{ background: #0f172a; color: #fff; border-color: #0f172a; }}
.pill.lat-pill-btn.on {{ background: #0f766e; border-color: #0f766e; }}

.tbl-wrap {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 24px rgba(15, 23, 42, 0.04); }}
table {{ width: 100%; border-collapse: collapse; }}
thead th {{
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #64748b;
  padding: 11px 14px;
  text-align: left;
  border-bottom: 1px solid #e2e8f0;
  background: #f8fafc;
  white-space: nowrap;
}}
tbody tr {{ border-bottom: 1px solid #eef2f7; transition: background 0.08s; }}
tbody tr:last-child {{ border-bottom: none; }}
tbody tr:hover {{ background: #f8fafc; }}
td {{ padding: 12px 14px; vertical-align: top; }}

.dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-top: 4px; flex-shrink: 0; }}
td:first-child {{ width: 24px; padding-right: 0; }}
.sev-cell {{ font-size: 12px; font-weight: 700; color: #334155; white-space: nowrap; }}
.ts {{ font-size: 11px; color: #64748b; font-variant-numeric: tabular-nums; white-space: nowrap; font-family: ui-monospace, monospace; }}
.name {{ font-size: 13px; color: #0f172a; font-weight: 650; }}
.desc {{ font-size: 12px; color: #64748b; margin-top: 2px; }}
.lat-pill {{
  display: inline-block;
  font-size: 10px;
  font-weight: 700;
  color: #92400e;
  background: #fef3c7;
  border: 1px solid #fde68a;
  border-radius: 999px;
  padding: 1px 7px;
  margin-left: 6px;
  vertical-align: middle;
  letter-spacing: 0.2px;
}}
.mono {{ font-family: ui-monospace, "SFMono-Regular", monospace; font-size: 12px; color: #334155; }}
.ip {{ color: #0369a1; }}
.mitre-id {{ font-family: ui-monospace, monospace; font-size: 11px; color: #6d28d9; display: block; font-weight: 700; }}
.mitre-name {{ font-size: 11px; color: #64748b; display: block; margin-top: 1px; }}

.empty {{ text-align: center; padding: 48px; color: #64748b; font-size: 13px; }}

footer {{
  margin-top: 24px;
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: #64748b;
  flex-wrap: wrap;
  gap: 8px;
}}
@media (max-width: 780px) {{
  .page {{ padding: 18px; }}
  .incident-head, .top {{ display: block; }}
  .incident-count, .generated {{ display: inline-block; margin-top: 10px; text-align: left; }}
  .incident-grid {{ grid-template-columns: 1fr; }}
  .tbl-wrap {{ overflow-x: auto; }}
  table {{ min-width: 780px; }}
}}
</style>
</head>
<body>
<div class="page">

  <div class="top">
    <div>
      <h1>SOC triage report</h1>
      <div class="meta">{filepath} &nbsp;·&nbsp; {line_count:,} lines parsed</div>
    </div>
    <div class="generated">Generated {generated_at}</div>
  </div>

  <div class="cards">
    <div class="card total"><div class="card-num">{len(alerts)}</div><div class="card-label">Total alerts</div></div>
    <div class="card crit"><div class="card-num">{counts['CRITICAL']}</div><div class="card-label">Critical</div></div>
    <div class="card high"><div class="card-num">{counts['HIGH']}</div><div class="card-label">High</div></div>
    <div class="card med"><div class="card-num">{counts['MEDIUM']}</div><div class="card-label">Medium</div></div>
    <div class="card low"><div class="card-num">{counts['LOW']}</div><div class="card-label">Low</div></div>
    <div class="card lateral"><div class="card-num">{lateral_count}</div><div class="card-label">Lateral movement</div></div>
  </div>

  {lateral_banner}

  <div class="section-title">Incident cases</div>
  {incidents_html if incidents else '<div class="empty">No incident cases to display.</div>'}

  <div class="section-title">Top entities</div>
  <div class="entity-grid">{top_html}</div>

  <div class="section-title">MITRE ATT&amp;CK summary</div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>Technique</th><th>Name</th><th>Alerts</th></tr></thead>
      <tbody>{summary_html if alerts else '<tr><td colspan="3" class="empty">No MITRE techniques to display.</td></tr>'}</tbody>
    </table>
  </div>

  <div class="toolbar">
    <span>Filter</span>
    <button class="pill on" onclick="filter('ALL',this)">All</button>
    <button class="pill" onclick="filter('CRITICAL',this)">Critical</button>
    <button class="pill" onclick="filter('HIGH',this)">High</button>
    <button class="pill" onclick="filter('MEDIUM',this)">Medium</button>
    <button class="pill" onclick="filter('LOW',this)">Low</button>
    <button class="pill lat-pill-btn" onclick="filter('LATERAL',this)">Lateral only</button>
  </div>

  <div class="section-title">Alert details</div>
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th></th>
          <th>Severity</th>
          <th>Timestamp</th>
          <th>Detection</th>
          <th>User</th>
          <th>IP / source</th>
          <th>Host</th>
          <th>MITRE</th>
        </tr>
      </thead>
      <tbody id="tbody">
        {rows_html if alerts else '<tr><td colspan="8" class="empty">No alerts to display.</td></tr>'}
      </tbody>
    </table>
  </div>

  <footer>
    <span>SOC Log Analyzer &nbsp;·&nbsp; MITRE ATT&amp;CK mapped</span>
    <span>{len(alerts)} alerts across {line_count:,} log lines</span>
  </footer>

</div>
<script>
  const rows = Array.from(document.querySelectorAll('#tbody tr[data-sev]'));
  function filter(f, btn) {{
    document.querySelectorAll('.pill').forEach(b => b.classList.remove('on'));
    btn.classList.add('on');
    rows.forEach(r => {{
      if (f === 'ALL') r.style.display = '';
      else if (f === 'LATERAL') r.style.display = r.dataset.lat === '1' ? '' : 'none';
      else r.style.display = r.dataset.sev === f ? '' : 'none';
    }});
  }}
</script>
</body>
</html>"""

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  [+] HTML dashboard exported → {outfile}\n")

# ── CSV / JSON Export ─────────────────────────────────────────────────────────

def export_csv(alerts, outfile):
    fields = ["timestamp", "detection_id", "severity", "name", "user", "ip", "host", "cmd",
              "mitre_id", "mitre_name", "lateral", "description", "raw"]
    with open(outfile, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for a in alerts:
            writer.writerow({k: a.get(k, "") for k in fields})
    print(f"\n  [+] Report exported → {outfile}\n")

def export_json(alerts, incidents, outfile):
    payload = {
        "alerts": alerts,
        "mitre_summary": mitre_summary(alerts),
        "top_entities": {
            "users": top_entities(alerts, "user"),
            "source_ips": top_entities(alerts, "ip"),
            "hosts": top_entities(alerts, "host"),
        },
        "incidents": [
            {
                **{k: v for k, v in incident.items() if k != "alerts"},
                "alerts": incident["alerts"],
            }
            for incident in incidents
        ],
    }
    with open(outfile, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n  [+] JSON exported → {outfile}\n")

def export_ticket(incidents, alerts, filepath, outfile):
    highest = highest_severity(alerts)
    lines = [
        f"# SOC Triage Ticket: {filepath}",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Incidents: {len(incidents)}",
        f"Alerts: {len(alerts)}",
        f"Highest Severity: {highest}",
        "",
        "## Executive Summary",
        "",
        f"The analyzer reviewed `{filepath}` and grouped {len(alerts)} alert(s) into {len(incidents)} incident case(s). Use this ticket as a starting point for validation, containment, and evidence collection.",
        "",
        "## MITRE ATT&CK Summary",
        "",
    ]
    for item in mitre_summary(alerts):
        lines.append(f"- `{item['mitre_id']}` {item['mitre_name']}: {item['count']} alert(s)")
    lines.append("")

    for incident in incidents:
        lines.extend([
            f"## {incident['id']}: {incident['title']}",
            "",
            f"- Severity: {incident['severity']}",
            f"- Risk Score: {incident['risk_score']}/100",
            f"- Verdict: {incident['verdict']}",
            f"- Confidence: {incident['confidence']}",
            f"- Verdict Reason: {incident['verdict_reason']}",
            f"- Window: {incident['first_seen']} -> {incident['last_seen']}",
            f"- Users: {', '.join(incident['users'])}",
            f"- IPs: {', '.join(incident['ips'])}",
            f"- Hosts: {', '.join(incident['hosts'])}",
            f"- Alert Count: {incident['alert_count']}",
            "",
            "### Evidence",
            "",
        ])
        for item in incident["evidence"]:
            lines.append(f"- {item}")
        lines.extend(["", "### Timeline", ""])
        for alert in incident["alerts"]:
            detail = ""
            fields = alert.get("windows_fields")
            if fields:
                detail = (
                    f" target={fields.get('target_user', '—')} subject={fields.get('subject_user', '—')}"
                    f" workstation={fields.get('workstation', '—')} auth={fields.get('auth_package', '—')}"
                )
            lines.append(f"- `{alert['timestamp']}` [{alert['severity']}] `{alert.get('detection_id', 'NO-ID')}` {alert['name']} (`{alert['mitre_id']}`) host={alert.get('host', 'unknown')}{detail}")
        lines.extend(["", "### Analyst Playbook", ""])
        for step in incident["playbook"]:
            lines.append(f"- {step}")
        lines.extend(["", "### Recommended Containment", ""])
        for step in incident["containment"]:
            lines.append(f"- {step}")
        lines.extend(["", "### Follow-Up Queries", ""])
        for query in incident["followup_queries"]:
            lines.append(f"- {query}")
        lines.extend(["", "### False Positive Considerations", ""])
        for note in incident["false_positive_notes"]:
            lines.append(f"- {note}")
        lines.extend(["", "### Risk Factors", ""])
        for reason in incident["risk_reasons"]:
            lines.append(f"- {reason}")
        lines.append("")

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n  [+] Markdown ticket exported → {outfile}\n")

    html_outfile = os.path.splitext(outfile)[0] + ".html"
    export_ticket_html(incidents, alerts, filepath, html_outfile)

def export_ticket_html(incidents, alerts, filepath, outfile):
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary_rows = ""
    for item in mitre_summary(alerts):
        summary_rows += f"""
        <tr>
          <td><code>{html_lib.escape(item['mitre_id'])}</code></td>
          <td>{html_lib.escape(item['mitre_name'])}</td>
          <td>{item['count']}</td>
        </tr>"""

    incident_sections = ""
    for incident in incidents:
        evidence = "".join(f"<li>{html_lib.escape(item)}</li>" for item in incident["evidence"])
        timeline = "".join(
            f"<li><code>{html_lib.escape(alert['timestamp'])}</code> "
            f"<strong>{html_lib.escape(alert['severity'])}</strong> "
            f"{html_lib.escape(alert['name'])} "
            f"<code>{html_lib.escape(alert['mitre_id'])}</code></li>"
            for alert in incident["alerts"]
        )
        playbook = "".join(f"<li>{html_lib.escape(step)}</li>" for step in incident["playbook"])
        containment = "".join(f"<li>{html_lib.escape(step)}</li>" for step in incident["containment"])
        followups = "".join(f"<li>{html_lib.escape(query)}</li>" for query in incident["followup_queries"])
        fp_notes = "".join(f"<li>{html_lib.escape(note)}</li>" for note in incident["false_positive_notes"])
        risk_reasons = "".join(f"<li>{html_lib.escape(reason)}</li>" for reason in incident["risk_reasons"])
        lateral = '<span class="pill">lateral</span>' if incident["lateral"] else ""

        incident_sections += f"""
      <section class="ticket">
        <div class="ticket-head">
          <div>
            <div class="eyebrow">{html_lib.escape(incident['id'])} · {html_lib.escape(incident['severity'])}</div>
            <h2>{html_lib.escape(incident['title'])} {lateral}</h2>
          </div>
          <div class="risk">Risk {incident['risk_score']}/100</div>
        </div>
        <dl>
          <div><dt>Window</dt><dd>{html_lib.escape(incident['first_seen'])} -> {html_lib.escape(incident['last_seen'])}</dd></div>
          <div><dt>Verdict</dt><dd>{html_lib.escape(incident['verdict'])} ({html_lib.escape(incident['confidence'])})</dd></div>
          <div><dt>Users</dt><dd>{html_lib.escape(', '.join(incident['users']))}</dd></div>
          <div><dt>IPs</dt><dd>{html_lib.escape(', '.join(incident['ips']))}</dd></div>
          <div><dt>Hosts</dt><dd>{html_lib.escape(', '.join(incident['hosts']))}</dd></div>
          <div><dt>Alerts</dt><dd>{incident['alert_count']}</dd></div>
        </dl>
        <p class="verdict-reason">{html_lib.escape(incident['verdict_reason'])}</p>
        <div class="grid">
          <div><h3>Evidence</h3><ul>{evidence}</ul></div>
          <div><h3>Risk Factors</h3><ul>{risk_reasons}</ul></div>
          <div><h3>Timeline</h3><ul>{timeline}</ul></div>
          <div><h3>Analyst Playbook</h3><ul>{playbook}</ul></div>
          <div><h3>Recommended Containment</h3><ul>{containment}</ul></div>
          <div><h3>Follow-Up Queries</h3><ul>{followups}</ul></div>
          <div><h3>False Positive Considerations</h3><ul>{fp_notes}</ul></div>
        </div>
      </section>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Ticket - {html_lib.escape(filepath)}</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  color: #172033;
  background: #f5f7fb;
  font-size: 14px;
  line-height: 1.5;
}}
.page {{ max-width: 1180px; margin: 0 auto; padding: 32px; }}
.top {{
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
  margin-bottom: 22px;
  background: #fff;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05);
}}
h1 {{ margin: 0; font-size: 24px; font-weight: 750; color: #0f172a; letter-spacing: 0; }}
.meta, .generated {{ color: #64748b; font-size: 12px; }}
.meta {{ margin-top: 6px; }}
.summary {{ max-width: 760px; margin: 12px 0 0; color: #475569; font-size: 13px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.card, .ticket, .table-wrap {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 10px 24px rgba(15, 23, 42, 0.04); }}
.card {{ padding: 16px; }}
.card strong {{ display: block; font-size: 30px; line-height: 1; margin-bottom: 6px; color: #0f172a; }}
.card span {{ color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
.ticket {{ padding: 20px; margin-bottom: 16px; border-left: 4px solid #0f766e; }}
.ticket-head {{ display: flex; justify-content: space-between; gap: 14px; align-items: flex-start; margin-bottom: 12px; }}
.eyebrow {{ color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
h2 {{ margin: 2px 0 0; font-size: 19px; color: #0f172a; letter-spacing: 0; }}
.risk {{ color: #991b1b; background: #fee2e2; border: 1px solid #fecaca; border-radius: 999px; padding: 5px 11px; font-size: 12px; font-weight: 700; white-space: nowrap; }}
.pill {{ color: #92400e; background: #fef3c7; border: 1px solid #fde68a; border-radius: 999px; padding: 2px 8px; font-size: 10px; font-weight: 700; vertical-align: middle; }}
dl {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 10px;
  margin: 0 0 16px;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 12px;
}}
dt {{ color: #64748b; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }}
dd {{ margin: 2px 0 0; font-family: ui-monospace, "SFMono-Regular", monospace; font-size: 12px; color: #334155; }}
.grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px 24px; }}
.verdict-reason {{ margin: 0 0 16px; color: #475569; background: #f8fafc; border-left: 3px solid #0f766e; padding: 10px 12px; border-radius: 6px; }}
h3 {{ margin: 0 0 7px; color: #475569; font-size: 12px; font-weight: 750; text-transform: uppercase; letter-spacing: 0.5px; }}
ul {{ margin: 0; padding-left: 18px; }}
li {{ margin-bottom: 6px; color: #334155; }}
code {{ font-family: ui-monospace, "SFMono-Regular", monospace; font-size: 12px; color: #6d28d9; font-weight: 700; }}
.section-title {{ margin: 26px 0 10px; color: #475569; font-size: 12px; font-weight: 750; text-transform: uppercase; letter-spacing: 0.5px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 11px 13px; border-bottom: 1px solid #eef2f7; text-align: left; vertical-align: top; }}
th {{ color: #64748b; background: #f8fafc; font-size: 11px; font-weight: 750; text-transform: uppercase; letter-spacing: 0.5px; }}
tr:last-child td {{ border-bottom: 0; }}
@media (max-width: 760px) {{
  .page {{ padding: 18px; }}
  .top, .ticket-head {{ display: block; }}
  .generated, .risk {{ margin-top: 8px; display: inline-block; }}
  .grid {{ grid-template-columns: 1fr; }}
  .table-wrap {{ overflow-x: auto; }}
  table {{ min-width: 560px; }}
}}
</style>
</head>
<body>
  <main class="page">
    <div class="top">
      <div>
        <h1>SOC Triage Ticket</h1>
        <div class="meta">{html_lib.escape(filepath)}</div>
        <p class="summary">Case-ready incident notes with evidence, timeline, containment, follow-up searches, and false-positive review context.</p>
      </div>
      <div class="generated">Generated {generated_at}</div>
    </div>

    <div class="cards">
      <div class="card"><strong>{len(incidents)}</strong><span>Incidents</span></div>
      <div class="card"><strong>{len(alerts)}</strong><span>Alerts</span></div>
      <div class="card"><strong>{sum(1 for a in alerts if a.get('lateral'))}</strong><span>Lateral indicators</span></div>
    </div>

    {incident_sections if incidents else '<section class="ticket">No incidents to display.</section>'}

    <div class="section-title">MITRE ATT&amp;CK Summary</div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Technique</th><th>Name</th><th>Alerts</th></tr></thead>
        <tbody>{summary_rows if alerts else '<tr><td colspan="3">No MITRE techniques to display.</td></tr>'}</tbody>
      </table>
    </div>
  </main>
</body>
</html>"""

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  [+] HTML ticket exported → {outfile}\n")

def export_timeline(incidents, filepath, outfile):
    rows = []
    for incident in incidents:
        for alert in incident["alerts"]:
            rows.append((alert_time(alert) or datetime.max, incident["id"], alert))
    rows.sort(key=lambda item: item[0])

    lines = [
        f"# Investigation Timeline: {filepath}",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "| Timestamp | Incident | Rule ID | Severity | Detection | User | IP | Host |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for _, incident_id, alert in rows:
        lines.append(
            f"| {alert['timestamp']} | {incident_id} | `{alert.get('detection_id', 'NO-ID')}` | "
            f"{alert['severity']} | {alert['name']} | {alert['user']} | {alert['ip']} | {alert.get('host', 'unknown')} |"
        )

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n  [+] Timeline exported → {outfile}\n")

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SOC Log Analyzer – cross-platform threat detection (Linux + Windows)"
    )
    parser.add_argument("--file",     required=False, help="Path to log file (.log or .csv)")
    parser.add_argument("--severity", default=None,  help="Filter: CRITICAL | HIGH | MEDIUM | LOW")
    parser.add_argument("--export",   default=None,  help="Export alerts to CSV")
    parser.add_argument("--json",     default=None,  help="Export alerts to JSON")
    parser.add_argument("--html",     default=None,  help="Export HTML dashboard")
    parser.add_argument("--ticket",   default=None,  help="Export Markdown incident ticket")
    parser.add_argument("--timeline", default=None,  help="Export Markdown investigation timeline")
    parser.add_argument("--config",   default=None,  help="Optional JSON config for thresholds, allowlists, and watchlists")
    parser.add_argument("--list-rules", action="store_true", help="List supported detection rules and exit")
    args = parser.parse_args()

    if args.list_rules:
        print_rules()
        return

    if not args.file:
        parser.error("--file is required unless --list-rules is used")

    try:
        load_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"\n[ERROR] Could not load config: {exc}")
        return

    result = analyze(args.file, args.severity)
    if not result:
        return

    alerts, line_count = result
    incidents = build_incidents(alerts)
    print_report(alerts, incidents, line_count, args.file)

    if args.export:
        export_csv(alerts, args.export)
    if args.json:
        export_json(alerts, incidents, args.json)
    if args.html:
        export_html(alerts, incidents, line_count, args.file, args.html)
    if args.ticket:
        export_ticket(incidents, alerts, args.file, args.ticket)
    if args.timeline:
        export_timeline(incidents, args.file, args.timeline)

if __name__ == "__main__":
    main()

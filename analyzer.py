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
import argparse
from datetime import datetime
from collections import defaultdict

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────

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
        "name": "Failed SSH Login",
        "pattern": re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+)",
            re.IGNORECASE,
        ),
        "key": "ssh_failed",
        "severity": "MEDIUM",
    },
    {
        "name": "Accepted SSH Login",
        "pattern": re.compile(
            r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.]+)",
            re.IGNORECASE,
        ),
        "key": "ssh_accepted",
        "severity": "LOW",
    },
    {
        "name": "sudo – Command Executed",
        "pattern": re.compile(
            r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)",
            re.IGNORECASE,
        ),
        "key": "sudo_escalation",
        "severity": "MEDIUM",
    },
    {
        "name": "sudo – Authentication Failure",
        "pattern": re.compile(
            r"sudo:.*authentication failure.*user=(?P<user>\S+)",
            re.IGNORECASE,
        ),
        "key": "repeated_sudo_fail",
        "severity": "HIGH",
    },
    {
        "name": "New User Created",
        "pattern": re.compile(
            r"new user:\s*name=(?P<user>\S+)",
            re.IGNORECASE,
        ),
        "key": "new_user_created",
        "severity": "HIGH",
    },
    {
        "name": "Root Login",
        "pattern": re.compile(
            r"(?:session opened for user root|Accepted .* for root from (?P<ip>[\d\.]+))",
            re.IGNORECASE,
        ),
        "key": "root_login",
        "severity": "HIGH",
    },
    {
        "name": "Password Changed",
        "pattern": re.compile(
            r"password changed for (?P<user>\S+)",
            re.IGNORECASE,
        ),
        "key": "password_changed",
        "severity": "MEDIUM",
    },
    {
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
        "name": "⚠ sudo to Different User (Lateral)",
        "pattern": re.compile(
            r"sudo:\s+(?P<user>\S+)\s*:.*USER=(?P<cmd>(?!root)\S+).*COMMAND=",
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
        "name": "⚠ Remote Scheduled Task Creation",
        "key": "scheduled_task_remote",
        "severity": "HIGH",
        "lateral": True,
        "event_ids": {"4698", "4702"},
        "conditions": lambda row, msg, logon_type, ip: True,
        "description": "Scheduled task created — possible remote execution pivot.",
    },
    {
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
        "name": "Failed Windows Logon",
        "key":  "win_failed_logon",
        "severity": "MEDIUM",
        "track_brute": True,
    },
    "4624": {
        "name": "Successful Windows Logon",
        "key":  "win_logon_success",
        "severity": "LOW",
        "rdp_check": True,
    },
    "4720": {
        "name": "User Account Created",
        "key":  "win_user_created",
        "severity": "HIGH",
    },
    "4726": {
        "name": "User Account Deleted",
        "key":  "win_user_deleted",
        "severity": "HIGH",
    },
    "4732": {
        "name": "User Added to Privileged Group",
        "key":  "win_priv_escalation",
        "severity": "HIGH",
    },
    "4648": {
        "name": "Logon with Explicit Credentials",
        "key":  "win_priv_escalation",
        "severity": "MEDIUM",
    },
    "1102": {
        "name": "⚠ Audit Log Cleared",
        "key":  "win_audit_cleared",
        "severity": "HIGH",
    },
    "7045": {
        "name": "New Service Installed",
        "key":  "win_service_install",
        "severity": "HIGH",
    },
    "4697": {
        "name": "Service Installed in System",
        "key":  "win_service_install",
        "severity": "HIGH",
    },
    "5140": {
        "name": "Network Share Accessed",
        "key":  "admin_share_access",
        "severity": "MEDIUM",
    },
    "5145": {
        "name": "Network Share Object Checked",
        "key":  "admin_share_access",
        "severity": "MEDIUM",
    },
    "4698": {
        "name": "Scheduled Task Created",
        "key":  "scheduled_task_remote",
        "severity": "HIGH",
    },
    "4702": {
        "name": "Scheduled Task Updated",
        "key":  "scheduled_task_remote",
        "severity": "HIGH",
    },
    "4776": {
        "name": "Failed Credential Validation (NTLM)",
        "key":  "win_failed_logon",
        "severity": "MEDIUM",
        "track_brute": True,
    },
}

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW    = 60  # seconds

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

def detect_format(filepath):
    with open(filepath, "r", errors="replace") as f:
        first_line = f.readline().lower()
    if "eventid" in first_line or "timecreated" in first_line or "timegenerated" in first_line:
        return "windows"
    return "linux"

# ── Windows CSV Parser ────────────────────────────────────────────────────────

def parse_windows_message(message):
    user, ip, logon_type = "unknown", "—", "—"
    m = re.search(r"Account Name:\s+(\S+)", message)
    if m and "$" not in m.group(1):
        user = m.group(1)
    m = re.search(r"Source Network Address:\s+([\d\.]+)", message)
    if m:
        ip = m.group(1)
    m = re.search(r"Logon Type:\s+(\d+)", message)
    if m:
        logon_type = m.group(1)
    return user, ip, logon_type

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
            user, ip, logon_type = parse_windows_message(message)

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
                        "severity":    lat_rule["severity"],
                        "name":        lat_rule["name"],
                        "user":        user,
                        "ip":          ip,
                        "cmd":         f"EventID:{event_id}  LogonType:{logon_type}",
                        "mitre_id":    mitre_id,
                        "mitre_name":  mitre_name,
                        "description": lat_rule.get("description", ""),
                        "lateral":     True,
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
            else:
                name = rule["name"]

            if rule.get("track_brute") and ip != "—" and ts:
                failed_by_ip[ip].append(ts)

            alerts.append({
                "timestamp":   ts.strftime("%Y-%m-%d %H:%M:%S") if ts else time_raw,
                "severity":    severity,
                "name":        name,
                "user":        user,
                "ip":          ip,
                "cmd":         f"EventID:{event_id}  LogonType:{logon_type}",
                "mitre_id":    mitre_id,
                "mitre_name":  mitre_name,
                "description": "",
                "lateral":     False,
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
                    "severity":    "HIGH",
                    "name":        "⚠  Brute Force Detected (Windows)",
                    "user":        "multiple",
                    "ip":          ip,
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

        for rule in LINUX_RULES:
            m = rule["pattern"].search(line)
            if not m:
                continue
            groups   = m.groupdict()
            user     = groups.get("user", "unknown")
            ip       = groups.get("ip",   "—")
            cmd      = groups.get("cmd",  "—")
            mitre_id, mitre_name = MITRE[rule["key"]]

            if rule["key"] == "ssh_failed" and ip != "—" and ts:
                failed_by_ip[ip].append(ts)

            # Track SSH acceptances per user for lateral-movement chaining
            if rule["key"] == "ssh_accepted" and ip != "—" and ts:
                ssh_sessions[user].append((ts, ip))

            alerts.append({
                "timestamp":   ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown",
                "severity":    rule["severity"],
                "name":        rule["name"],
                "user":        user,
                "ip":          ip,
                "cmd":         cmd,
                "mitre_id":    mitre_id,
                "mitre_name":  mitre_name,
                "description": "",
                "lateral":     rule.get("lateral", False),
                "raw":         line.strip(),
            })

    # ── Linux lateral movement: same user logging in from multiple IPs quickly ─
    LATERAL_IP_THRESHOLD  = 2   # ≥2 different source IPs
    LATERAL_TIME_WINDOW   = 300  # within 5 minutes
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
                    "severity":    "HIGH",
                    "name":        "⚠ Lateral Movement – Multi-Source SSH",
                    "user":        user,
                    "ip":          ", ".join(sorted(unique_ips)),
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
                    "severity":    "HIGH",
                    "name":        "⚠  Brute Force Detected",
                    "user":        "multiple",
                    "ip":          ip,
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

def print_report(alerts, line_count, filepath):
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
    if lateral_count:
        print(colorize(f"  Lateral Move  : {lateral_count} indicator(s) detected", "CRITICAL"))
    print("═" * 70 + "\n")

    if not alerts:
        print("  No alerts matched. Try running without --severity to see all findings.\n")
        return

    for a in alerts:
        sev_label = f"[{a['severity']:<8}]"
        prefix = "  🔴 " if a.get("lateral") else "     "
        print(prefix + colorize(sev_label, a["severity"]) + f"  {a['timestamp']}  {a['name']}")
        print(f"               User : {a['user']}   IP : {a['ip']}")
        if a["cmd"] not in ("—", ""):
            print(f"               Info : {a['cmd'][:80]}")
        if a.get("description"):
            print(f"               Note : {a['description']}")
        print(f"               MITRE: {a['mitre_id']} – {a['mitre_name']}")
        print(f"               Raw  : {a['raw'][:100]}")
        print()

    print("═" * 70)
    print("  Tip: Run with --html report.html for a visual dashboard.")
    print("═" * 70 + "\n")

# ── HTML Dashboard ────────────────────────────────────────────────────────────

def export_html(alerts, line_count, filepath, outfile):
    counts = defaultdict(int)
    for a in alerts:
        counts[a["severity"]] += 1
    lateral_count = sum(1 for a in alerts if a.get("lateral"))
    generated_at  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build alert rows
    rows_html = ""
    for a in alerts:
        sev = a["severity"]
        sev_class = {
            "CRITICAL": "sev-critical",
            "HIGH":     "sev-high",
            "MEDIUM":   "sev-medium",
            "LOW":      "sev-low",
        }.get(sev, "sev-low")
        lateral_badge = '<span class="badge-lateral">LATERAL</span>' if a.get("lateral") else ""
        desc_cell = f'<div class="alert-desc">{a["description"]}</div>' if a.get("description") else ""
        rows_html += f"""
        <tr class="alert-row {'lateral-row' if a.get('lateral') else ''}">
          <td><span class="sev-badge {sev_class}">{sev}</span>{lateral_badge}</td>
          <td class="ts-cell">{a['timestamp']}</td>
          <td>
            <span class="alert-name">{a['name']}</span>
            {desc_cell}
          </td>
          <td>{a['user']}</td>
          <td class="ip-cell">{a['ip']}</td>
          <td class="mitre-cell"><code>{a['mitre_id']}</code><br><span class="mitre-name">{a['mitre_name']}</span></td>
          <td class="raw-cell"><span class="raw-text">{a['raw'][:120]}</span></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Triage Report — {filepath}</title>
<style>
  :root {{
    --bg:        #0d0f14;
    --surface:   #141720;
    --surface2:  #1c2030;
    --border:    #252a3a;
    --text:      #c9d1e0;
    --muted:     #5a6070;
    --accent:    #4e7fff;
    --critical:  #d43fff;
    --high:      #ff4e4e;
    --medium:    #f5a623;
    --low:       #4ec9ff;
    --lateral:   #ff2d78;
    --font-mono: "JetBrains Mono", "Fira Code", "Cascadia Code", monospace;
    --font-ui:   "Inter", "Segoe UI", system-ui, sans-serif;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-ui);
    font-size: 13px;
    line-height: 1.5;
    min-height: 100vh;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #0d0f14 0%, #141a2e 100%);
    border-bottom: 1px solid var(--border);
    padding: 28px 36px 24px;
  }}
  .header-top {{
    display: flex;
    align-items: flex-start;
    gap: 16px;
    margin-bottom: 20px;
  }}
  .header-icon {{
    font-size: 32px;
    line-height: 1;
    flex-shrink: 0;
    margin-top: 4px;
  }}
  .header-title h1 {{
    font-family: var(--font-mono);
    font-size: 22px;
    font-weight: 600;
    color: #fff;
    letter-spacing: -0.3px;
  }}
  .header-title .subtitle {{
    color: var(--muted);
    font-size: 12px;
    margin-top: 3px;
  }}
  .header-meta {{
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
  }}
  .meta-item {{
    display: flex;
    flex-direction: column;
    gap: 2px;
  }}
  .meta-label {{ color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: 0.8px; }}
  .meta-value {{ color: var(--text); font-family: var(--font-mono); font-size: 12px; }}

  /* ── Stat Cards ── */
  .stats {{
    display: flex;
    gap: 12px;
    padding: 20px 36px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }}
  .stat-card {{
    flex: 1;
    min-width: 110px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    position: relative;
    overflow: hidden;
  }}
  .stat-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
  }}
  .stat-card.critical::before {{ background: var(--critical); }}
  .stat-card.high::before     {{ background: var(--high); }}
  .stat-card.medium::before   {{ background: var(--medium); }}
  .stat-card.low::before      {{ background: var(--low); }}
  .stat-card.lateral-card::before {{ background: var(--lateral); }}
  .stat-card.total::before    {{ background: var(--accent); }}

  .stat-num {{
    font-family: var(--font-mono);
    font-size: 28px;
    font-weight: 700;
    line-height: 1;
  }}
  .stat-card.critical .stat-num {{ color: var(--critical); }}
  .stat-card.high .stat-num     {{ color: var(--high); }}
  .stat-card.medium .stat-num   {{ color: var(--medium); }}
  .stat-card.low .stat-num      {{ color: var(--low); }}
  .stat-card.lateral-card .stat-num {{ color: var(--lateral); }}
  .stat-card.total .stat-num    {{ color: var(--accent); }}

  .stat-label {{
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }}

  /* ── Lateral Banner ── */
  .lateral-banner {{
    background: linear-gradient(90deg, rgba(255, 45, 120, 0.12), transparent);
    border-left: 3px solid var(--lateral);
    margin: 20px 36px 0;
    padding: 12px 16px;
    border-radius: 0 6px 6px 0;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 13px;
  }}
  .lateral-banner .icon {{ font-size: 18px; }}
  .lateral-banner strong {{ color: var(--lateral); }}

  /* ── Filters ── */
  .filters {{
    padding: 16px 36px;
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }}
  .filters label {{ color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; margin-right: 4px; }}
  .filter-btn {{
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--muted);
    border-radius: 4px;
    padding: 4px 12px;
    cursor: pointer;
    font-family: var(--font-ui);
    font-size: 12px;
    transition: all 0.15s;
  }}
  .filter-btn:hover {{ border-color: var(--accent); color: var(--text); }}
  .filter-btn.active {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
  .filter-btn.lat-filter.active {{ background: var(--lateral); border-color: var(--lateral); }}

  /* ── Table ── */
  .table-wrap {{
    padding: 0 36px 36px;
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }}
  thead th {{
    background: var(--surface);
    color: var(--muted);
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 0.8px;
    font-weight: 600;
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
    position: sticky;
    top: 0;
    z-index: 1;
  }}
  tr.alert-row {{
    border-bottom: 1px solid var(--border);
    transition: background 0.1s;
  }}
  tr.alert-row:hover {{ background: var(--surface2); }}
  tr.lateral-row {{ background: rgba(255, 45, 120, 0.04); }}
  tr.lateral-row:hover {{ background: rgba(255, 45, 120, 0.09); }}
  td {{
    padding: 10px 12px;
    vertical-align: top;
  }}

  .sev-badge {{
    display: inline-block;
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 3px;
    letter-spacing: 0.5px;
  }}
  .sev-critical {{ background: rgba(212,63,255,0.18); color: var(--critical); border: 1px solid rgba(212,63,255,0.3); }}
  .sev-high     {{ background: rgba(255,78,78,0.15);  color: var(--high);     border: 1px solid rgba(255,78,78,0.3); }}
  .sev-medium   {{ background: rgba(245,166,35,0.15); color: var(--medium);   border: 1px solid rgba(245,166,35,0.3); }}
  .sev-low      {{ background: rgba(78,201,255,0.12); color: var(--low);      border: 1px solid rgba(78,201,255,0.3); }}

  .badge-lateral {{
    display: inline-block;
    margin-left: 5px;
    font-size: 9px;
    font-weight: 700;
    padding: 1px 5px;
    border-radius: 3px;
    background: rgba(255,45,120,0.2);
    color: var(--lateral);
    border: 1px solid rgba(255,45,120,0.4);
    letter-spacing: 0.5px;
    vertical-align: middle;
  }}

  .alert-name {{ color: #e2e8f0; font-weight: 500; }}
  .alert-desc {{ color: var(--muted); font-size: 11px; margin-top: 3px; }}

  .ts-cell {{ font-family: var(--font-mono); color: var(--muted); white-space: nowrap; font-size: 11px; }}
  .ip-cell  {{ font-family: var(--font-mono); color: var(--accent); font-size: 11px; }}
  .mitre-cell code {{ color: var(--medium); font-family: var(--font-mono); font-size: 11px; }}
  .mitre-name {{ color: var(--muted); font-size: 10px; }}
  .raw-cell {{ max-width: 300px; }}
  .raw-text {{ font-family: var(--font-mono); font-size: 10px; color: var(--muted); word-break: break-all; }}

  .no-results {{
    text-align: center;
    padding: 60px 0;
    color: var(--muted);
  }}

  /* ── Footer ── */
  .footer {{
    border-top: 1px solid var(--border);
    padding: 16px 36px;
    color: var(--muted);
    font-size: 11px;
    display: flex;
    justify-content: space-between;
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="header-icon">🔍</div>
    <div class="header-title">
      <h1>SOC Log Analyzer — Triage Report</h1>
      <div class="subtitle">Automated threat detection · MITRE ATT&amp;CK mapped</div>
    </div>
  </div>
  <div class="header-meta">
    <div class="meta-item"><span class="meta-label">File</span><span class="meta-value">{filepath}</span></div>
    <div class="meta-item"><span class="meta-label">Lines Parsed</span><span class="meta-value">{line_count:,}</span></div>
    <div class="meta-item"><span class="meta-label">Generated</span><span class="meta-value">{generated_at}</span></div>
  </div>
</div>

<div class="stats">
  <div class="stat-card total">
    <span class="stat-num">{len(alerts)}</span>
    <span class="stat-label">Total Alerts</span>
  </div>
  <div class="stat-card critical">
    <span class="stat-num">{counts['CRITICAL']}</span>
    <span class="stat-label">Critical</span>
  </div>
  <div class="stat-card high">
    <span class="stat-num">{counts['HIGH']}</span>
    <span class="stat-label">High</span>
  </div>
  <div class="stat-card medium">
    <span class="stat-num">{counts['MEDIUM']}</span>
    <span class="stat-label">Medium</span>
  </div>
  <div class="stat-card low">
    <span class="stat-num">{counts['LOW']}</span>
    <span class="stat-label">Low</span>
  </div>
  <div class="stat-card lateral-card">
    <span class="stat-num">{lateral_count}</span>
    <span class="stat-label">Lateral Movement</span>
  </div>
</div>

{"" if not lateral_count else f'''
<div class="lateral-banner">
  <span class="icon">⚠️</span>
  <span><strong>Lateral Movement Indicators Detected</strong> — {lateral_count} alert(s) suggest attacker pivoting between hosts. Review LATERAL-tagged rows immediately.</span>
</div>
'''}

<div class="filters">
  <label>Filter:</label>
  <button class="filter-btn active" onclick="filterAlerts('ALL', this)">All</button>
  <button class="filter-btn" onclick="filterAlerts('CRITICAL', this)">Critical</button>
  <button class="filter-btn" onclick="filterAlerts('HIGH', this)">High</button>
  <button class="filter-btn" onclick="filterAlerts('MEDIUM', this)">Medium</button>
  <button class="filter-btn" onclick="filterAlerts('LOW', this)">Low</button>
  <button class="filter-btn lat-filter" onclick="filterAlerts('LATERAL', this)">Lateral Only</button>
</div>

<div class="table-wrap">
  <table id="alert-table">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Timestamp</th>
        <th>Detection</th>
        <th>User</th>
        <th>IP / Source</th>
        <th>MITRE</th>
        <th>Raw</th>
      </tr>
    </thead>
    <tbody id="alert-body">
      {rows_html if alerts else '<tr><td colspan="7" class="no-results">No alerts to display.</td></tr>'}
    </tbody>
  </table>
</div>

<div class="footer">
  <span>SOC Log Analyzer · MITRE ATT&amp;CK Framework</span>
  <span>{len(alerts)} alerts across {line_count:,} log lines</span>
</div>

<script>
  const rows = Array.from(document.querySelectorAll('#alert-body tr.alert-row'));

  function filterAlerts(sev, btn) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    rows.forEach(r => {{
      if (sev === 'ALL') {{
        r.style.display = '';
      }} else if (sev === 'LATERAL') {{
        r.style.display = r.classList.contains('lateral-row') ? '' : 'none';
      }} else {{
        const badge = r.querySelector('.sev-badge');
        r.style.display = badge && badge.textContent.trim() === sev ? '' : 'none';
      }}
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
    fields = ["timestamp", "severity", "name", "user", "ip", "cmd",
              "mitre_id", "mitre_name", "lateral", "description", "raw"]
    with open(outfile, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for a in alerts:
            writer.writerow({k: a.get(k, "") for k in fields})
    print(f"\n  [+] Report exported → {outfile}\n")

def export_json(alerts, outfile):
    with open(outfile, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"\n  [+] JSON exported → {outfile}\n")

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SOC Log Analyzer – cross-platform threat detection (Linux + Windows)"
    )
    parser.add_argument("--file",     required=True, help="Path to log file (.log or .csv)")
    parser.add_argument("--severity", default=None,  help="Filter: CRITICAL | HIGH | MEDIUM | LOW")
    parser.add_argument("--export",   default=None,  help="Export alerts to CSV")
    parser.add_argument("--json",     default=None,  help="Export alerts to JSON")
    parser.add_argument("--html",     default=None,  help="Export HTML dashboard")
    args = parser.parse_args()

    result = analyze(args.file, args.severity)
    if not result:
        return

    alerts, line_count = result
    print_report(alerts, line_count, args.file)

    if args.export:
        export_csv(alerts, args.export)
    if args.json:
        export_json(alerts, args.json)
    if args.html:
        export_html(alerts, line_count, args.file, args.html)

if __name__ == "__main__":
    main()

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

MITRE =
{
    "brute_force":         ("T1110",     "Brute Force"),
    "failed_login":        ("T1078",     "Valid Accounts – Failed Attempt"),
    "sudo_escalation":     ("T1548.003", "Abuse Elevation Control – sudo"),
    "new_user_created":    ("T1136",     "Create Account"),
    "ssh_accepted":        ("T1021.004", "Remote Services – SSH"),
    "ssh_failed":          ("T1110.004", "Brute Force – Credential Stuffing"),
    "session_opened":      ("T1078",     "Valid Accounts – Session"),
    "root_login":          ("T1078.003", "Valid Accounts – Local Accounts (root)"),
    "password_changed":    ("T1531",     "Account Access Removal / Credential Change"),
    "repeated_sudo_fail":  ("T1548",     "Abuse Elevation Control"),
    # Windows-specific
    "win_failed_logon":    ("T1110",     "Brute Force – Failed Windows Logon"),
    "win_user_created":    ("T1136.001", "Create Account – Local Account"),
    "win_user_deleted":    ("T1531",     "Account Access Removal"),
    "win_rdp_logon":       ("T1021.001", "Remote Services – RDP"),
    "win_priv_escalation": ("T1548",     "Abuse Elevation Control"),
    "win_logon_success":   ("T1078",     "Valid Accounts – Successful Logon"),
    "win_audit_cleared":   ("T1070.001", "Indicator Removal – Clear Windows Event Logs"),
    "win_service_install": ("T1543.003", "Create or Modify System Process – Windows Service"),
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
]

# ── Windows Event ID Rules ────────────────────────────────────────────────────
# Maps Windows Security Event IDs to detection logic

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
        "rdp_check": True,   # escalate to HIGH if LogonType=10 (RDP)
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

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

def colorize(text, severity):
    if not COLOR:
        return text
    colors = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN}
    return colors.get(severity, "") + text + Style.RESET_ALL

def parse_timestamp(line):
    """Extract datetime from common log formats."""
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
    """Auto-detect whether file is Windows CSV or Linux syslog."""
    with open(filepath, "r", errors="replace") as f:
        first_line = f.readline().lower()
    if "eventid" in first_line or "timecreated" in first_line or "timegenerated" in first_line:
        return "windows"
    return "linux"

# ── Windows CSV Parser ────────────────────────────────────────────────────────

def parse_windows_message(message):
    """Extract user, IP, logon type from Windows event message text."""
    user, ip, logon_type = "unknown", "—", "—"
    m = re.search(r"Account Name:\s+(\S+)", message)
    if m and "$" not in m.group(1):   # skip machine accounts ending in $
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

        # Normalize column names (strip quotes/spaces)
        reader.fieldnames = [h.strip().strip('"') for h in (reader.fieldnames or [])]

        for row in reader:
            line_count += 1

            # Support both Get-EventLog and Get-WinEvent export column names
            event_id  = (row.get("EventID") or row.get("Id") or "").strip().strip('"')
            time_raw  = (row.get("TimeGenerated") or row.get("TimeCreated") or "").strip().strip('"')
            message   = (row.get("Message") or "").strip().strip('"')

            if event_id not in WINDOWS_EVENT_RULES:
                continue

            rule = WINDOWS_EVENT_RULES[event_id]
            ts   = parse_timestamp(time_raw) or parse_timestamp(message)
            user, ip, logon_type = parse_windows_message(message)
            mitre_id, mitre_name = MITRE[rule["key"]]

            severity = rule["severity"]

            # Escalate RDP logons to HIGH
            if rule.get("rdp_check") and logon_type == "10":
                severity = "HIGH"
                name = "RDP Logon (Remote Desktop)"
                mitre_id, mitre_name = MITRE["win_rdp_logon"]
            else:
                name = rule["name"]

            # Track for brute force correlation
            if rule.get("track_brute") and ip != "—" and ts:
                failed_by_ip[ip].append(ts)

            alerts.append({
                "timestamp":  ts.strftime("%Y-%m-%d %H:%M:%S") if ts else time_raw,
                "severity":   severity,
                "name":       name,
                "user":       user,
                "ip":         ip,
                "cmd":        f"EventID:{event_id}  LogonType:{logon_type}",
                "mitre_id":   mitre_id,
                "mitre_name": mitre_name,
                "raw":        message[:120],
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
                    "timestamp":  window[0].strftime("%Y-%m-%d %H:%M:%S"),
                    "severity":   "HIGH",
                    "name":       "⚠  Brute Force Detected (Windows)",
                    "user":       "multiple",
                    "ip":         ip,
                    "cmd":        "EventID:4625",
                    "mitre_id":   mitre_id,
                    "mitre_name": mitre_name,
                    "raw":        f"[CORRELATED] {BRUTE_FORCE_THRESHOLD} failed logons from {ip} within {int(delta)}s",
                })
                break

    if severity_filter:
        alerts = [a for a in alerts if a["severity"] == severity_filter.upper()]

    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 9))
    return alerts, line_count

# ── Linux/macOS Parser ────────────────────────────────────────────────────────

def analyze_linux(filepath, severity_filter=None):
    alerts = []
    failed_by_ip = defaultdict(list)
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
            groups = m.groupdict()
            user   = groups.get("user", "unknown")
            ip     = groups.get("ip",   "—")
            cmd    = groups.get("cmd",  "—")
            mitre_id, mitre_name = MITRE[rule["key"]]

            if rule["key"] == "ssh_failed" and ip != "—" and ts:
                failed_by_ip[ip].append(ts)

            alerts.append({
                "timestamp":  ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "unknown",
                "severity":   rule["severity"],
                "name":       rule["name"],
                "user":       user,
                "ip":         ip,
                "cmd":        cmd,
                "mitre_id":   mitre_id,
                "mitre_name": mitre_name,
                "raw":        line.strip(),
            })

    for ip, timestamps in failed_by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps) - BRUTE_FORCE_THRESHOLD + 1):
            window = timestamps[i: i + BRUTE_FORCE_THRESHOLD]
            delta  = (window[-1] - window[0]).total_seconds()
            if delta <= BRUTE_FORCE_WINDOW:
                mitre_id, mitre_name = MITRE["brute_force"]
                alerts.append({
                    "timestamp":  window[0].strftime("%Y-%m-%d %H:%M:%S"),
                    "severity":   "HIGH",
                    "name":       "⚠  Brute Force Detected",
                    "user":       "multiple",
                    "ip":         ip,
                    "cmd":        "—",
                    "mitre_id":   mitre_id,
                    "mitre_name": mitre_name,
                    "raw":        f"[CORRELATED] {BRUTE_FORCE_THRESHOLD} failed logins from {ip} within {int(delta)}s",
                })
                break

    if severity_filter:
        alerts = [a for a in alerts if a["severity"] == severity_filter.upper()]

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

# ── Output ────────────────────────────────────────────────────────────────────

def print_report(alerts, line_count, filepath):
    counts = defaultdict(int)
    for a in alerts:
        counts[a["severity"]] += 1

    print("\n" + "═" * 70)
    print("  SOC LOG ANALYZER — TRIAGE REPORT")
    print("═" * 70)
    print(f"  File     : {filepath}")
    print(f"  Lines    : {line_count:,}")
    print(f"  Alerts   : {len(alerts)}  "
          f"[HIGH: {counts['HIGH']}  MEDIUM: {counts['MEDIUM']}  LOW: {counts['LOW']}]")
    print("═" * 70 + "\n")

    if not alerts:
        print("  No alerts matched. Try running without --severity to see all findings.\n")
        return

    for a in alerts:
        sev_label = f"[{a['severity']:<6}]"
        print(colorize(sev_label, a["severity"]) + f"  {a['timestamp']}  {a['name']}")
        print(f"           User : {a['user']}   IP : {a['ip']}")
        if a["cmd"] not in ("—", ""):
            print(f"           Info : {a['cmd'][:80]}")
        print(f"           MITRE: {a['mitre_id']} – {a['mitre_name']}")
        print(f"           Raw  : {a['raw'][:100]}")
        print()

    print("═" * 70)
    print("  Tip: Run with --export report.csv to save results.")
    print("═" * 70 + "\n")

def export_csv(alerts, outfile):
    fields = ["timestamp", "severity", "name", "user", "ip", "cmd",
              "mitre_id", "mitre_name", "raw"]
    with open(outfile, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for a in alerts:
            writer.writerow({k: a[k] for k in fields})
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
    parser.add_argument("--severity", default=None,  help="Filter: HIGH | MEDIUM | LOW")
    parser.add_argument("--export",   default=None,  help="Export alerts to CSV")
    parser.add_argument("--json",     default=None,  help="Export alerts to JSON")
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

if __name__ == "__main__":
    main()

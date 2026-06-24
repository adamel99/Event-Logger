# SOC Log Analyzer

A cross-platform threat detection tool that parses Linux auth logs and Windows Event Log exports, detects suspicious patterns — including lateral movement — maps findings to MITRE ATT&CK, and outputs a color-coded triage report or interactive HTML dashboard.

---

## Features

- **Lateral movement detection** — Pass-the-Hash, PsExec, WMI execution, DCOM, SMB admin shares, remote scheduled tasks, token impersonation, and multi-source SSH pivoting
- **Brute force correlation engine** — correlates failed logins across a sliding time window, not just per-line
- **Detects** failed/accepted SSH logins, privilege escalation, new account creation, root logins, RDP sessions, audit log clearing, and service installs
- **Auto-detects** Linux/macOS syslog or Windows Event Log CSV format
- **MITRE ATT&CK mapped** — every alert includes technique ID and name
- **Interactive HTML dashboard** — dark-themed, filterable by severity and lateral movement indicators
- **Exports** to CSV, JSON, or HTML

---

## Installation

```bash
git clone https://github.com/yourname/soc-log-analyzer.git
cd soc-log-analyzer
pip3 install colorama
```

---

## Usage

```bash
# Linux/macOS auth log
python3 analyzer.py --file sample_logs/auth.log

# Windows Event Log CSV
python3 analyzer.py --file sample_logs/windows_security.csv

# Filter by severity
python3 analyzer.py --file sample_logs/auth.log --severity HIGH

# Export results
python3 analyzer.py --file sample_logs/auth.log --export report.csv
python3 analyzer.py --file sample_logs/auth.log --json report.json

# Generate HTML dashboard
python3 analyzer.py --file sample_logs/auth.log --html report.html
```

---

## Quick Test

No log file handy? Use the included sample:

```bash
python3 analyzer.py --file sample_logs/test.log --html report.html
```

Then open `report.html` in your browser. You should see 14 alerts including brute force, lateral movement, and account creation detections.

---

## Detections & MITRE ATT&CK Coverage

### Linux / macOS

| Detection | MITRE ID | Severity |
|---|---|---|
| Failed SSH Login | T1110.004 | MEDIUM |
| Accepted SSH Login | T1021.004 | LOW |
| Brute Force (correlated) | T1110 | HIGH |
| sudo Command Executed | T1548.003 | MEDIUM |
| sudo Authentication Failure | T1548 | HIGH |
| New User Created | T1136 | HIGH |
| Root Login | T1078.003 | HIGH |
| Password Changed | T1531 | MEDIUM |
| Multi-Source SSH (Lateral) | T1021.004 | HIGH |
| SSH Key-Hopping (Lateral) | T1021.004 | HIGH |

### Windows Event Log

| Detection | Event ID | MITRE ID | Severity |
|---|---|---|---|
| Failed Logon | 4625 | T1110 | MEDIUM |
| Successful Logon | 4624 | T1078 | LOW |
| RDP Logon | 4624 (type 10) | T1021.001 | HIGH |
| User Account Created | 4720 | T1136.001 | HIGH |
| User Account Deleted | 4726 | T1531 | HIGH |
| Added to Privileged Group | 4732 | T1548 | HIGH |
| Explicit Credential Logon | 4648 | T1548 | MEDIUM |
| Audit Log Cleared | 1102 | T1070.001 | HIGH |
| Service Installed | 7045 / 4697 | T1543.003 | HIGH |
| Admin Share Access | 5140 / 5145 | T1077 | MEDIUM |
| Remote Scheduled Task | 4698 / 4702 | T1053.005 | HIGH |
| Pass-the-Hash | 4624 | T1550.002 | CRITICAL |
| PsExec / Remote Execution | 7045 | T1569.002 | CRITICAL |
| WMI Execution | 4624 / 4648 | T1047 | HIGH |
| DCOM Execution | 4624 | T1021.003 | HIGH |
| Token Impersonation | 4624 | T1134 | HIGH |

---

## Exporting Windows Event Logs

To generate a compatible CSV from a Windows machine:

```powershell
Get-WinEvent -LogName Security -MaxEvents 500 |
  Select-Object Id, TimeCreated, Message |
  Export-Csv security.csv -NoTypeInformation
```

---

## Output Example (terminal)

```
══════════════════════════════════════════════════════════════════════
  SOC LOG ANALYZER — TRIAGE REPORT
══════════════════════════════════════════════════════════════════════
  File          : sample_logs/test.log
  Lines         : 10
  Alerts        : 14  [CRITICAL: 0  HIGH: 6  MEDIUM: 5  LOW: 3]
  Lateral Move  : 3 indicator(s) detected
══════════════════════════════════════════════════════════════════════

  🔴 [HIGH    ]  2024-06-10 09:01:00  ⚠ Lateral Movement – Multi-Source SSH
                 User : jsmith   IP : 10.0.0.9, 10.0.0.11
                 Note : User 'jsmith' authenticated from 2 different IPs within 300s
                 MITRE: T1021.004 – Remote Services – SSH (Lateral)
```

---

## Requirements

- Python 3.7+
- `colorama` (optional, for color terminal output)

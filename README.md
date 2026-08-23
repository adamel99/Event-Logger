# SOC Log Analyzer

> A cross-platform threat detection engine that analyzes Windows Event Log exports and Linux authentication logs, correlates suspicious activity, maps detections to MITRE ATT&CK, and generates triage-ready reports.

---

## Overview

SOC Log Analyzer is a Python-based security tool designed to emulate core detection workflows used by Security Operations Centers (SOCs).

Rather than treating each log entry independently, the analyzer correlates related events across configurable time windows to identify suspicious behavior such as brute force attacks, lateral movement, privilege escalation, and credential abuse.

Every detection includes:

- MITRE ATT&CK technique mapping
- Severity classification
- Human-readable explanation
- Incident case grouping
- Chronological investigation timeline
- Analyst playbook guidance
- Risk scoring and evidence summaries
- Analyst verdict and confidence
- Detection rule IDs
- Host, user, and source IP summaries
- MITRE ATT&CK summary table
- Rule listing command
- Config validation with clear error messages
- Optional Markdown incident ticket export
- Terminal output
- Optional HTML dashboard
- CSV and JSON export

The project supports both Windows Security Event Log exports and Linux authentication logs.

---

## Why I Built This

Many introductory security projects simply search logs for known Event IDs.

The goal of this project was to build something closer to how security analysts investigate incidents.

Instead of matching individual events, the analyzer performs behavioral correlation across multiple log entries to reduce false positives and generate more meaningful alerts.

---

# Features

## Detection Engine

- Sliding-window brute force correlation
- Incident case correlation
- Chronological timeline generation
- Analyst triage playbooks
- Evidence summaries
- MITRE ATT&CK reporting
- Top users, source IPs, and hosts
- Timeline export
- False-positive context from expected admin activity
- Configurable thresholds, allowlists, admin users, and watchlists
- Lateral movement detection
- Privilege escalation detection
- Credential abuse detection
- Account management monitoring
- Authentication monitoring

---

## Supported Attack Techniques

### Linux

- Failed SSH logins
- Successful SSH logins
- Root logins
- sudo execution
- sudo authentication failures
- New user creation
- Password changes
- Multi-source SSH authentication
- SSH key hopping

### Windows

- Failed logons
- Successful logons
- RDP logons
- User creation
- User deletion
- Privileged group membership changes
- Explicit credential logons
- Audit log clearing
- Service installation
- SMB Admin Share access
- Remote scheduled tasks
- Pass-the-Hash
- PsExec execution
- WMI execution
- DCOM execution
- Token impersonation

---

# Detection Workflow

```
                 Windows Event Logs
                          │
                          │
                 Linux auth.log
                          │
                          ▼
                  Log Format Detection
                          │
                          ▼
                     Log Parsing
                          │
                          ▼
                 Correlation Engine
                          │
                          ▼
                 Detection Rules
                          │
                          ▼
                Incident Correlation
                          │
                          ▼
                Timeline Generation
                          │
                          ▼
                 Analyst Playbooks
                          │
                          ▼
              MITRE ATT&CK Mapping
                          │
                          ▼
             Severity Classification
                          │
          ┌───────────────┴───────────────┐
          ▼                               ▼
   Terminal Report                 HTML Dashboard
                                   CSV Export
                                   JSON Export
                                   Markdown Ticket
                                   Timeline Export
```

---

# Detection Logic

Unlike traditional log parsers that evaluate one event at a time, SOC Log Analyzer correlates multiple events before generating alerts.

Examples include:

## Brute Force

Tracks repeated authentication failures from the same source within a configurable sliding time window.

Instead of generating dozens of individual alerts, the analyzer creates a single high-confidence brute force detection.

---

## Multi-Source SSH Authentication

Detects when the same user successfully authenticates from multiple IP addresses within a short period.

This may indicate lateral movement between systems.

---

## Pass-the-Hash

Correlates Windows authentication events commonly associated with NTLM credential reuse to identify potential Pass-the-Hash activity.

---

## Remote Execution

Identifies indicators consistent with:

- PsExec
- WMI
- DCOM
- Remote Scheduled Tasks

to highlight potential lateral movement.

---

# MITRE ATT&CK Coverage

## Linux

| Detection | MITRE | Severity |
|------------|--------|----------|
| Failed SSH Login | T1110.004 | MEDIUM |
| Accepted SSH Login | T1021.004 | LOW |
| Brute Force | T1110 | HIGH |
| sudo Command | T1548.003 | MEDIUM |
| sudo Authentication Failure | T1548 | HIGH |
| New User Created | T1136 | HIGH |
| Root Login | T1078.003 | HIGH |
| Password Changed | T1531 | MEDIUM |
| Multi-Source SSH | T1021.004 | HIGH |
| SSH Key Hopping | T1021.004 | HIGH |

---

## Windows

| Detection | Event ID | MITRE | Severity |
|------------|----------|--------|----------|
| Failed Logon | 4625 | T1110 | MEDIUM |
| Successful Logon | 4624 | T1078 | LOW |
| RDP Logon | 4624 | T1021.001 | HIGH |
| User Created | 4720 | T1136.001 | HIGH |
| User Deleted | 4726 | T1531 | HIGH |
| Privileged Group | 4732 | T1548 | HIGH |
| Explicit Credentials | 4648 | T1548 | MEDIUM |
| Audit Logs Cleared | 1102 | T1070.001 | HIGH |
| Service Installed | 7045 / 4697 | T1543.003 | HIGH |
| SMB Admin Share | 5140 / 5145 | T1077 | MEDIUM |
| Remote Scheduled Task | 4698 / 4702 | T1053.005 | HIGH |
| Pass-the-Hash | 4624 | T1550.002 | CRITICAL |
| PsExec | 7045 | T1569.002 | CRITICAL |
| WMI | 4624 / 4648 | T1047 | HIGH |
| DCOM | 4624 | T1021.003 | HIGH |
| Token Impersonation | 4624 | T1134 | HIGH |

---

# Installation

Clone the repository:

```bash
git clone https://github.com/adamel99/Event-Logger.git

cd Event-Logger
```

Install the dependency:

```bash
pip install colorama
```

---

# Usage

## Quick Start

Install the dependency:

```bash
python3 -m pip install colorama
```

List supported detection rules:

```bash
python3 analyzer.py --list-rules
```

Run the included Linux sample:

```bash
python3 analyzer.py --file sample_logs/auth.log
```

Generate the HTML dashboard:

```bash
python3 analyzer.py --file sample_logs/auth.log --html report.html
```

Generate a Markdown incident ticket:

```bash
python3 analyzer.py --file sample_logs/auth.log --ticket incident-ticket.md
```

Generate a chronological investigation timeline:

```bash
python3 analyzer.py --file sample_logs/auth.log --timeline timeline.md
```

Export machine-readable results:

```bash
python3 analyzer.py --file sample_logs/auth.log --export report.csv --json report.json
```

Run with demo config tuning, allowlists, admin users, and watchlists:

```bash
python3 analyzer.py --file sample_logs/auth.log --config config/demo_config.json
```

Filter to high-severity findings only:

```bash
python3 analyzer.py --file sample_logs/auth.log --severity HIGH
```

Analyze a Windows Event Log CSV export:

```bash
python3 analyzer.py --file windows_security.csv
```

Run the included Windows sample:

```bash
python3 analyzer.py --file sample_logs/windows_security.csv --ticket windows-ticket.md --html report.html
```

## Demo Scenarios

The `sample_logs/scenarios/` folder contains focused logs for demos and testing:

```text
sample_logs/scenarios/linux_bruteforce_success.auth.log
sample_logs/scenarios/linux_false_positive_admin.auth.log
sample_logs/scenarios/linux_lateral_sudo.auth.log
sample_logs/windows_security.csv
```

Example commands:

```bash
python3 analyzer.py --file sample_logs/scenarios/linux_bruteforce_success.auth.log --ticket brute-force-ticket.md
python3 analyzer.py --file sample_logs/scenarios/linux_false_positive_admin.auth.log --config config/demo_config.json
python3 analyzer.py --file sample_logs/scenarios/linux_lateral_sudo.auth.log --html report.html
python3 analyzer.py --file sample_logs/windows_security.csv --json windows-report.json
```

## Config File

`config/demo_config.json` lets you tune detections without editing Python code:

```json
{
  "brute_force_threshold": 5,
  "brute_force_window_seconds": 60,
  "incident_window_seconds": 600,
  "lateral_ssh_window_seconds": 300,
  "known_good_ips": ["10.0.0.20"],
  "admin_users": ["admin"],
  "watchlist_users": ["root", "backdoor"]
}
```

These values affect brute force thresholds, incident grouping windows, lateral SSH windows, and triage context labels.

If the config file has an invalid value, the analyzer prints a direct error such as:

```text
[ERROR] Could not load config: brute_force_threshold must be an integer
```

## Log Source Guide

See [docs/log-sources.md](docs/log-sources.md) for Linux auth log examples, Windows CSV export commands, required columns, optional host fields, and safe handling notes for real logs.

## What Goes Into `auth.log`

The Linux parser expects normal syslog-style authentication lines. You can use real Linux `/var/log/auth.log` entries, copied lab logs, or synthetic demo logs.

Supported examples:

```text
Jun 10 09:00:01 server sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2
Jun 10 09:00:45 server sshd[6]: Accepted password for root from 10.0.0.5 port 22 ssh2
Jun 10 09:01:00 server sshd[7]: Accepted publickey for jsmith from 10.0.0.9 port 22 ssh2 pts/0
Jun 10 09:01:30 server sshd[8]: Accepted publickey for jsmith from 10.0.0.11 port 22 ssh2 pts/1
Jun 10 09:02:00 server sudo[9]: jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash
Jun 10 09:02:20 server sudo[10]: pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 tty=/dev/pts/0 ruser=jsmith rhost= user=jsmith
Jun 10 09:03:00 server useradd[11]: new user: name=backdoor, UID=0, GID=0, home=/root
Jun 10 09:04:00 server sshd[12]: session opened for user root by (uid=0)
```

The analyzer currently recognizes failed SSH logins, accepted SSH logins, root sessions, sudo commands, sudo authentication failures, password changes, new user creation, and multi-source SSH activity.

## Reading the Output

The terminal report has two main sections:

- `INCIDENT CASES`: grouped alerts with a timeline and analyst playbook steps.
- `TOP ENTITIES`: most active users, source IPs, and hosts.
- `MITRE ATT&CK SUMMARY`: technique IDs and alert counts.
- `ALERT DETAILS`: individual detections with user, IP, raw log snippet, severity, and MITRE mapping.

Example incident flow:

```text
INC-001 [HIGH] Possible Compromise After Brute Force
Window : 2026-06-10 09:00:01 -> 2026-06-10 09:04:00
Risk   : 100/100
Evidence:
  - 5 failed logins within 8s
  - Successful authentication for root from 10.0.0.5
Timeline:
  - Failed SSH Login
  - Brute Force Detected
  - Accepted SSH Login
  - sudo - Command Executed
  - New User Created
Analyst playbook:
  - Check whether the same source IP later achieved a successful login.
  - Review commands, process creation, and session activity immediately after authentication.
  - Check for persistence, new accounts, modified SSH keys, and unusual service changes.
```

## Markdown Ticket Export

Use `--ticket` when you want an analyst-ready case note:

```bash
python3 analyzer.py --file sample_logs/auth.log --ticket incident-ticket.md
```

The ticket includes:

- Incident title, severity, risk score, affected users, and source IPs
- Evidence summary
- Timeline
- Analyst playbook
- Risk factors
- MITRE ATT&CK summary

---

# Sample Output

```
══════════════════════════════════════════════════════════════

SOC LOG ANALYZER

══════════════════════════════════════════════════════════════

Alerts: 14

Critical: 0

High: 6

Medium: 5

Low: 3

Lateral Movement Indicators: 3

══════════════════════════════════════════════════════════════

[HIGH]

Multi-Source SSH Authentication

User: jsmith

IPs: 10.0.0.9, 10.0.0.11

MITRE: T1021.004
```

---

# Exporting Windows Event Logs

Generate a compatible CSV using PowerShell:

```powershell
Get-WinEvent -LogName Security -MaxEvents 500 |
Select-Object Id, TimeCreated, Message |
Export-Csv security.csv -NoTypeInformation
```

---

# Project Structure

```
soc-log-analyzer/

├── analyzer.py
├── README.md
├── .gitignore
├── config/
│   └── demo_config.json
├── report.html
└── sample_logs/
    ├── auth.log
    ├── windows_security.csv
    └── scenarios/
        ├── linux_bruteforce_success.auth.log
        ├── linux_false_positive_admin.auth.log
        └── linux_lateral_sudo.auth.log
```

---

# Future Improvements

- Real-time log monitoring
- Sigma rule support
- Splunk HEC integration
- Elastic Stack integration
- Docker deployment
- Email alerting
- Additional Windows Event ID coverage

---

# Requirements

- Python 3.7+
- colorama

---

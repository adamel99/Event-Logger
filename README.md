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

Linux authentication logs

```bash
python analyzer.py --file sample_logs/auth.log
```

Windows Event Log CSV

```bash
python analyzer.py --file windows_security.csv
```

Filter alerts

```bash
python analyzer.py --file sample_logs/auth.log --severity HIGH
```

Generate HTML dashboard

```bash
python analyzer.py --file sample_logs/auth.log --html report.html
```

Export CSV

```bash
python analyzer.py --file sample_logs/auth.log --export report.csv
```

Export JSON

```bash
python analyzer.py --file sample_logs/auth.log --json report.json
```

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
├── report.html
└── sample_logs/
    └── auth.log
```

---

# Future Improvements

- Real-time log monitoring
- Sigma rule support
- Splunk HEC integration
- Elastic Stack integration
- Docker deployment
- Email alerting
- Detection rule configuration file
- Additional Windows Event ID coverage

---

# Requirements

- Python 3.7+
- colorama

---



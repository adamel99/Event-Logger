# SOC Log Analyzer

A cross-platform threat detection tool that parses Linux auth logs
and Windows Event Log exports, detects suspicious patterns, maps
findings to MITRE ATT&CK, and outputs a color-coded triage report.

## Features
- Detects brute force, privilege escalation, new accounts, RDP logins and more
- Auto-detects Linux or Windows log format
- MITRE ATT&CK mapped alerts
- Exports to CSV and JSON
- Brute force correlation engine

## Usage
python analyzer.py --file sample_logs/auth.log
python analyzer.py --file sample_logs/windows_security.csv
python analyzer.py --file sample_logs/auth.log --severity HIGH
python analyzer.py --file sample_logs/auth.log --export report.csv

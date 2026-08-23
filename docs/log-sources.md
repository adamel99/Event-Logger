# Log Source Guide

This project supports two input types:

- Linux/macOS syslog-style authentication logs
- Windows Security Event Log CSV exports

Use this guide when creating new sample logs, exporting lab logs, or explaining the project in an interview.

## Linux Authentication Logs

Typical source:

```text
/var/log/auth.log
```

Common on:

- Ubuntu
- Debian
- Kali
- many Debian-based lab VMs

Run the analyzer:

```bash
python3 analyzer.py --file sample_logs/auth.log
```

Expected format:

```text
Jun 10 09:00:01 server sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2
Jun 10 09:00:45 server sshd[6]: Accepted password for root from 10.0.0.5 port 22 ssh2
Jun 10 09:02:00 server sudo[9]: jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash
Jun 10 09:03:00 server useradd[11]: new user: name=backdoor, UID=0, GID=0, home=/root
```

The parser uses the syslog hostname field as the affected host:

```text
Jun 10 09:00:01 server ...
                  ^^^^^^ host
```

Supported Linux detections include:

- failed SSH logins
- successful SSH logins
- root logins
- sudo commands
- sudo authentication failures
- new user creation
- password changes
- multi-source SSH activity
- SSH key-hopping indicators

## Windows Event Log CSV

Typical source:

```powershell
Get-WinEvent -LogName Security -MaxEvents 500 |
Select-Object Id, TimeCreated, ProviderName, MachineName, Message |
Export-Csv security.csv -NoTypeInformation
```

Run the analyzer:

```bash
python3 analyzer.py --file sample_logs/windows_security.csv
```

Minimum useful columns:

```text
Id, TimeCreated, Message
```

Recommended columns:

```text
Id, TimeCreated, MachineName, Message
```

The analyzer also recognizes these host/computer fields if present:

```text
Computer
MachineName
Host
Hostname
```

Example CSV:

```csv
"Id","TimeCreated","MachineName","Message"
"4625","2026-06-10 09:00:01","WIN-DC01","An account failed to log on. Account Name: alice Source Network Address: 10.0.0.55 Logon Type: 3"
"4624","2026-06-10 09:01:00","WIN-DC01","An account was successfully logged on. Account Name: alice Source Network Address: 10.0.0.55 Logon Type: 10"
"7045","2026-06-10 09:03:00","WIN-SRV01","A service was installed in the system. Account Name: alice Source Network Address: 10.0.0.55 Service Name: PSEXESVC"
```

Supported Windows detections include:

- failed logons
- successful logons
- RDP logons
- user creation/deletion
- privileged group membership changes
- explicit credential logons
- audit log clearing
- service installation
- SMB admin share access
- remote scheduled tasks
- Pass-the-Hash indicators
- PsExec indicators
- WMI/DCOM remote execution indicators
- token impersonation indicators

## Real Log Safety

Do not commit real production logs.

Real logs can contain:

- usernames
- hostnames
- public IP addresses
- internal IP ranges
- domain names
- service names
- command history
- sensitive paths

The `.gitignore` already excludes common local real-log names:

```text
sample_logs/windows_security_real.csv
sample_logs/auth_real.log
```

For public demos, use sanitized logs or synthetic scenario logs.

Safe substitutions:

```text
real username     -> alice
real hostname     -> WIN-SRV01
real internal IP  -> 10.0.0.55
real public IP    -> 203.0.113.10
real domain       -> example.local
```

## Useful Demo Commands

List supported detection rules:

```bash
python3 analyzer.py --list-rules
```

Run Linux sample:

```bash
python3 analyzer.py --file sample_logs/auth.log --html report.html --timeline timeline.md
```

Run Windows sample:

```bash
python3 analyzer.py --file sample_logs/windows_security.csv --ticket windows-ticket.md
```

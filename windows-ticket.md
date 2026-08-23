# SOC Triage Ticket: sample_logs/windows_security.csv

Generated: 2026-08-23 05:22:01
Incidents: 1
Alerts: 14

## MITRE ATT&CK Summary

- `T1110` Brute Force – Failed Windows Logon: 6 alert(s)
- `T1021.001` Remote Services – RDP: 1 alert(s)
- `T1021.002` Remote Services – SMB/Windows Admin Shares: 1 alert(s)
- `T1047` Windows Management Instrumentation: 1 alert(s)
- `T1070.001` Indicator Removal – Clear Windows Event Logs: 1 alert(s)
- `T1077` Windows Admin Shares: 1 alert(s)
- `T1543.003` Create or Modify System Process – Windows Service: 1 alert(s)
- `T1548` Abuse Elevation Control: 1 alert(s)
- `T1569.002` System Services – Service Execution (PsExec): 1 alert(s)

## INC-001: Possible Lateral Movement

- Severity: CRITICAL
- Risk Score: 100/100
- Verdict: Likely True Positive
- Confidence: High
- Verdict Reason: High-risk chained behavior or critical activity was observed.
- Window: 2026-06-10 09:00:01 -> 2026-06-10 09:04:00
- Users: alice
- IPs: 10.0.0.55
- Hosts: unknown
- Alert Count: 14

### Evidence

- 5 failed logons within 15s
- Successful authentication for alice from 10.0.0.55
- WMI-based remote process execution detected.
- Access to administrative share from remote IP.
- PsExec service or remote execution artifact detected.
- Observed user(s): alice

### Timeline

- `2026-06-10 09:00:01` [HIGH] `WIN-AUTH-005` ⚠  Brute Force Detected (Windows) (`T1110`) host=unknown
- `2026-06-10 09:00:01` [MEDIUM] `WIN-AUTH-001` Failed Windows Logon (`T1110`) host=unknown
- `2026-06-10 09:00:05` [MEDIUM] `WIN-AUTH-001` Failed Windows Logon (`T1110`) host=unknown
- `2026-06-10 09:00:09` [MEDIUM] `WIN-AUTH-001` Failed Windows Logon (`T1110`) host=unknown
- `2026-06-10 09:00:12` [MEDIUM] `WIN-AUTH-001` Failed Windows Logon (`T1110`) host=unknown
- `2026-06-10 09:00:16` [MEDIUM] `WIN-AUTH-001` Failed Windows Logon (`T1110`) host=unknown
- `2026-06-10 09:01:00` [HIGH] `WIN-AUTH-004` RDP Logon (Remote Desktop) (`T1021.001`) host=unknown
- `2026-06-10 09:02:00` [HIGH] `WIN-LAT-003` ⚠ WMI Remote Execution (`T1047`) host=unknown
- `2026-06-10 09:02:00` [MEDIUM] `WIN-PRIV-002` Logon with Explicit Credentials (`T1548`) host=unknown
- `2026-06-10 09:02:20` [HIGH] `WIN-LAT-004` ⚠ Admin Share Access (SMB Lateral Movement) (`T1021.002`) host=unknown
- `2026-06-10 09:02:20` [MEDIUM] `WIN-SMB-001` Network Share Accessed (`T1077`) host=unknown
- `2026-06-10 09:03:00` [CRITICAL] `WIN-LAT-002` ⚠ PsExec / Remote Service Execution (`T1569.002`) host=unknown
- `2026-06-10 09:03:00` [HIGH] `WIN-SVC-001` New Service Installed (`T1543.003`) host=unknown
- `2026-06-10 09:04:00` [HIGH] `WIN-EVASION-001` ⚠ Audit Log Cleared (`T1070.001`) host=unknown

### Analyst Playbook

- Check whether the same source IP later achieved a successful login.
- Review the targeted account for lockouts, MFA prompts, password changes, and recent privilege use.
- Look up the source IP in firewall, VPN, EDR, and threat intelligence logs.
- Validate whether the login source, time, and account are expected for this user.
- Review commands, process creation, and session activity immediately after authentication.
- Build a host-to-host timeline to determine the original entry point and next pivot.

### Risk Factors

- +10 highest medium activity present
- +22 highest high activity present
- +35 highest critical activity present
- +25 brute force pattern
- +25 lateral movement indicator

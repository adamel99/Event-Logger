# SOC Triage Ticket: sample_logs/scenarios/windows_psexec_lateral.csv

Generated: 2026-08-23 20:05:01
Incidents: 1
Alerts: 11
Highest Severity: CRITICAL

## Executive Summary

The analyzer reviewed `sample_logs/scenarios/windows_psexec_lateral.csv` and grouped 11 alert(s) into 1 incident case(s). Use this ticket as a starting point for validation, containment, and evidence collection.

## MITRE ATT&CK Summary

- `T1110` Brute Force – Failed Windows Logon: 6 alert(s)
- `T1070.001` Indicator Removal – Clear Windows Event Logs: 1 alert(s)
- `T1078` Valid Accounts – Successful Logon: 1 alert(s)
- `T1543.003` Create or Modify System Process – Windows Service: 1 alert(s)
- `T1550.002` Use Alternate Authentication Material – Pass the Hash: 1 alert(s)
- `T1569.002` System Services – Service Execution (PsExec): 1 alert(s)

## INC-001: Possible Compromise After Brute Force

- Severity: CRITICAL
- Risk Score: 100/100
- Verdict: Likely True Positive
- Confidence: High
- Verdict Reason: High-risk chained behavior or critical activity was observed.
- Window: 2026-06-14 02:10:01 -> 2026-06-14 02:14:45
- Users: svc-backup
- IPs: 10.0.0.55
- Hosts: WIN-DC01, WIN-SRV01
- Alert Count: 11

### Evidence

- 5 failed logons within 16s
- Network logon via NTLM from remote IP — possible Pass-the-Hash.
- Successful authentication for svc-backup from 10.0.0.55
- PsExec service or remote execution artifact detected.
- Observed user(s): svc-backup
- Observed source IP(s): 10.0.0.55

### Timeline

- `2026-06-14 02:10:01` [HIGH] `WIN-AUTH-005` ⚠  Brute Force Detected (Windows) (`T1110`) host=unknown
- `2026-06-14 02:10:01` [MEDIUM] `WIN-AUTH-001` Failed Windows Logon (`T1110`) host=WIN-DC01 target=svc-backup subject=— workstation=WS-144 auth=NTLM
- `2026-06-14 02:10:05` [MEDIUM] `WIN-AUTH-001` Failed Windows Logon (`T1110`) host=WIN-DC01 target=svc-backup subject=— workstation=WS-144 auth=NTLM
- `2026-06-14 02:10:09` [MEDIUM] `WIN-AUTH-001` Failed Windows Logon (`T1110`) host=WIN-DC01 target=svc-backup subject=— workstation=WS-144 auth=NTLM
- `2026-06-14 02:10:13` [MEDIUM] `WIN-AUTH-001` Failed Windows Logon (`T1110`) host=WIN-DC01 target=svc-backup subject=— workstation=WS-144 auth=NTLM
- `2026-06-14 02:10:17` [MEDIUM] `WIN-AUTH-001` Failed Windows Logon (`T1110`) host=WIN-DC01 target=svc-backup subject=— workstation=WS-144 auth=NTLM
- `2026-06-14 02:11:00` [CRITICAL] `WIN-LAT-001` ⚠ Pass-the-Hash Detected (`T1550.002`) host=WIN-SRV01 target=svc-backup subject=WS-144$ workstation=WS-144 auth=NTLM
- `2026-06-14 02:11:00` [LOW] `WIN-AUTH-002` Successful Windows Logon (`T1078`) host=WIN-SRV01 target=svc-backup subject=WS-144$ workstation=WS-144 auth=NTLM
- `2026-06-14 02:12:10` [CRITICAL] `WIN-LAT-002` ⚠ PsExec / Remote Service Execution (`T1569.002`) host=WIN-SRV01 target=svc-backup subject=svc-backup workstation=WS-144 auth=—
- `2026-06-14 02:12:10` [HIGH] `WIN-SVC-001` New Service Installed (`T1543.003`) host=WIN-SRV01 target=svc-backup subject=svc-backup workstation=WS-144 auth=—
- `2026-06-14 02:14:45` [HIGH] `WIN-EVASION-001` ⚠ Audit Log Cleared (`T1070.001`) host=WIN-SRV01 target=svc-backup subject=svc-backup workstation=WS-144 auth=NTLM

### Analyst Playbook

- Check whether the same source IP later achieved a successful login.
- Review the targeted account for lockouts, MFA prompts, password changes, and recent privilege use.
- Look up the source IP in firewall, VPN, EDR, and threat intelligence logs.
- Validate whether the login source, time, and account are expected for this user.
- Review commands, process creation, and session activity immediately after authentication.
- Build a host-to-host timeline to determine the original entry point and next pivot.

### Recommended Containment

- Block or rate-limit the source IP if activity is unauthorized and still active.
- Reset credentials or enforce MFA for targeted accounts if compromise is suspected.
- Temporarily disable or isolate the affected account if the login cannot be validated.
- Isolate affected hosts from peer systems while confirming the pivot path.
- Preserve remaining SIEM, EDR, firewall, and endpoint evidence before normal cleanup.

### Follow-Up Queries

- Search authentication events for (user="svc-backup") during the incident window.
- Search network, VPN, firewall, and EDR telemetry for (source_ip="10.0.0.55").
- Search process, service, scheduled task, and account changes for (host="WIN-DC01" OR host="WIN-SRV01").

### False Positive Considerations

- Confirm whether the activity matches an approved change window, helpdesk ticket, admin task, or vulnerability scan.
- Validate whether the source IP belongs to VPN, jump box, scanner, backup, or management infrastructure.

### Risk Factors

- +22 highest high activity present
- +3 highest low activity present
- +35 highest critical activity present
- +10 highest medium activity present
- +25 brute force pattern
- +30 successful login after authentication failures

# SOC Triage Ticket: sample_logs/scenarios/linux_bruteforce_success.auth.log

Generated: 2026-08-23 20:03:26
Incidents: 2
Alerts: 12
Highest Severity: HIGH

## Executive Summary

The analyzer reviewed `sample_logs/scenarios/linux_bruteforce_success.auth.log` and grouped 12 alert(s) into 2 incident case(s). Use this ticket as a starting point for validation, containment, and evidence collection.

## MITRE ATT&CK Summary

- `T1110.004` Brute Force – Credential Stuffing: 5 alert(s)
- `T1078.003` Valid Accounts – Local Accounts (root): 2 alert(s)
- `T1021.004` Remote Services – SSH: 1 alert(s)
- `T1078` Valid Accounts – Session: 1 alert(s)
- `T1110` Brute Force: 1 alert(s)
- `T1136` Create Account: 1 alert(s)
- `T1548.003` Abuse Elevation Control – sudo: 1 alert(s)

## INC-001: Possible Compromise After Brute Force

- Severity: HIGH
- Risk Score: 100/100
- Verdict: Likely True Positive
- Confidence: High
- Verdict Reason: High-risk chained behavior or critical activity was observed.
- Window: 2026-06-10 09:00:01 -> 2026-06-10 09:04:00
- Users: root
- IPs: 10.0.0.5
- Hosts: server
- Alert Count: 11

### Evidence

- 5 failed logins within 8s
- Successful authentication for root from 10.0.0.5
- Privilege activity by root: /usr/bin/cat /etc/shadow
- Observed user(s): root
- Observed source IP(s): 10.0.0.5

### Timeline

- `2026-06-10 09:00:01` [HIGH] `LINUX-SSH-003` ⚠  Brute Force Detected (`T1110`) host=unknown
- `2026-06-10 09:00:01` [MEDIUM] `LINUX-SSH-001` Failed SSH Login (`T1110.004`) host=server
- `2026-06-10 09:00:03` [MEDIUM] `LINUX-SSH-001` Failed SSH Login (`T1110.004`) host=server
- `2026-06-10 09:00:05` [MEDIUM] `LINUX-SSH-001` Failed SSH Login (`T1110.004`) host=server
- `2026-06-10 09:00:07` [MEDIUM] `LINUX-SSH-001` Failed SSH Login (`T1110.004`) host=server
- `2026-06-10 09:00:09` [MEDIUM] `LINUX-SSH-001` Failed SSH Login (`T1110.004`) host=server
- `2026-06-10 09:00:45` [HIGH] `LINUX-AUTH-001` Root Login (`T1078.003`) host=server
- `2026-06-10 09:00:45` [LOW] `LINUX-SSH-002` Accepted SSH Login (`T1021.004`) host=server
- `2026-06-10 09:02:00` [MEDIUM] `LINUX-PRIV-001` sudo – Command Executed (`T1548.003`) host=server
- `2026-06-10 09:04:00` [HIGH] `LINUX-AUTH-001` Root Login (`T1078.003`) host=server
- `2026-06-10 09:04:00` [LOW] `LINUX-SESSION-001` Session Opened (`T1078`) host=server

### Analyst Playbook

- Check whether the same source IP later achieved a successful login.
- Review the targeted account for lockouts, MFA prompts, password changes, and recent privilege use.
- Look up the source IP in firewall, VPN, EDR, and threat intelligence logs.
- Validate whether the login source, time, and account are expected for this user.
- Review commands, process creation, and session activity immediately after authentication.
- Review privileged commands and confirm they match an approved admin change.

### Recommended Containment

- Block or rate-limit the source IP if activity is unauthorized and still active.
- Reset credentials or enforce MFA for targeted accounts if compromise is suspected.
- Temporarily disable or isolate the affected account if the login cannot be validated.

### Follow-Up Queries

- Search authentication events for (user="root") during the incident window.
- Search network, VPN, firewall, and EDR telemetry for (source_ip="10.0.0.5").
- Search process, service, scheduled task, and account changes for (host="server").

### False Positive Considerations

- Confirm whether the activity matches an approved change window, helpdesk ticket, admin task, or vulnerability scan.
- Validate whether the source IP belongs to VPN, jump box, scanner, backup, or management infrastructure.

### Risk Factors

- +10 highest medium activity present
- +3 highest low activity present
- +22 highest high activity present
- +25 brute force pattern
- +30 successful login after authentication failures
- +20 privilege or root activity

## INC-002: Suspicious Account Management

- Severity: HIGH
- Risk Score: 47/100
- Verdict: Informational
- Confidence: Low
- Verdict Reason: Low-risk activity with limited malicious indicators.
- Window: 2026-06-10 09:03:00 -> 2026-06-10 09:03:00
- Users: backdoor
- IPs: —
- Hosts: server
- Alert Count: 1

### Evidence

- Account creation observed for backdoor
- Observed user(s): backdoor

### Timeline

- `2026-06-10 09:03:00` [HIGH] `LINUX-ACCT-001` New User Created (`T1136`) host=server

### Analyst Playbook

- Confirm the account owner, ticket/change request, group membership, and UID/GID values.
- Disable or contain the account if ownership cannot be validated quickly.

### Recommended Containment

- Disable newly created accounts until ownership and change approval are confirmed.

### Follow-Up Queries

- Search authentication events for (user="backdoor") during the incident window.
- Search network, VPN, firewall, and EDR telemetry for (source_ip="unknown").
- Search process, service, scheduled task, and account changes for (host="server").

### False Positive Considerations

- Confirm whether the activity matches an approved change window, helpdesk ticket, admin task, or vulnerability scan.
- Validate whether the source IP belongs to VPN, jump box, scanner, backup, or management infrastructure.

### Risk Factors

- +22 highest high activity present
- +25 account creation

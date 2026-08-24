# Investigation Scenarios

These scenarios are designed for portfolio demos and interview walkthroughs. Each one shows the command to run, what should fire, and how an analyst would explain the result.

## Linux Brute Force Followed by Compromise

Run:

```bash
python3 analyzer.py --file sample_logs/scenarios/linux_bruteforce_success.auth.log --ticket brute-force-ticket.md
```

Expected findings:

- `LINUX-SSH-003` brute force correlation
- `LINUX-SSH-002` successful SSH login
- `LINUX-PRIV-001` sudo command
- `LINUX-ACCT-001` suspicious user creation

Analyst interpretation:

Repeated root failures from one source were followed by a successful login, privileged command execution, and account creation. This should be treated as a likely true positive until the account owner, source IP, and commands are validated.

## Benign Admin Activity

Run:

```bash
python3 analyzer.py --file sample_logs/scenarios/linux_false_positive_admin.auth.log --config config/demo_config.json
```

Expected findings:

- SSH and sudo activity
- Known-good admin context from `config/demo_config.json`
- Lower analyst verdict due to expected admin activity

Analyst interpretation:

The behavior can look suspicious in isolation, but config context shows an expected admin user, source IP, host, and approved command. This demonstrates false-positive handling and detection tuning.

## Linux Lateral SSH and Sudo Activity

Run:

```bash
python3 analyzer.py --file sample_logs/scenarios/linux_lateral_sudo.auth.log --html report.html
```

Expected findings:

- `LINUX-LAT-003` multi-source SSH authentication
- sudo execution and sudo authentication failure
- watchlist context for `svc-backup`

Analyst interpretation:

The same user authenticating from multiple IPs in a short period followed by privilege activity can indicate host-to-host pivoting. Build a timeline around the user and inspect destination hosts.

## Windows RDP From Unusual Source

Run:

```bash
python3 analyzer.py --file sample_logs/scenarios/windows_rdp_unusual.csv --ticket windows-rdp-ticket.md
```

Expected findings:

- `WIN-AUTH-004` RDP logon
- extracted Windows fields such as source IP, workstation, logon type, and authentication package

Analyst interpretation:

Successful RDP from an external or unusual source needs validation against VPN, jump-box, and user travel context. Failed logons before the session would raise confidence.

## Windows PsExec Lateral Movement

Run:

```bash
python3 analyzer.py --file sample_logs/scenarios/windows_psexec_lateral.csv --ticket windows-psexec-ticket.md
```

Expected findings:

- Windows brute force correlation
- successful network logon
- `WIN-LAT-002` PsExec or remote service execution
- `WIN-EVASION-001` audit log clearing

Analyst interpretation:

Authentication failures, successful remote logon, service installation, and log clearing create a strong lateral movement and defense evasion chain. This should be escalated quickly.

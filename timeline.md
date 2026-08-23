# Investigation Timeline: sample_logs/auth.log

Generated: 2026-08-23 05:22:01

| Timestamp | Incident | Rule ID | Severity | Detection | User | IP | Host |
|---|---|---|---|---|---|---|---|
| 2026-06-10 09:00:01 | INC-001 | `LINUX-SSH-003` | HIGH | ⚠  Brute Force Detected | multiple | 10.0.0.5 | unknown |
| 2026-06-10 09:00:01 | INC-001 | `LINUX-SSH-001` | MEDIUM | Failed SSH Login | root | 10.0.0.5 | server |
| 2026-06-10 09:00:03 | INC-001 | `LINUX-SSH-001` | MEDIUM | Failed SSH Login | root | 10.0.0.5 | server |
| 2026-06-10 09:00:05 | INC-001 | `LINUX-SSH-001` | MEDIUM | Failed SSH Login | root | 10.0.0.5 | server |
| 2026-06-10 09:00:07 | INC-001 | `LINUX-SSH-001` | MEDIUM | Failed SSH Login | root | 10.0.0.5 | server |
| 2026-06-10 09:00:09 | INC-001 | `LINUX-SSH-001` | MEDIUM | Failed SSH Login | root | 10.0.0.5 | server |
| 2026-06-10 09:00:45 | INC-001 | `LINUX-AUTH-001` | HIGH | Root Login | root | 10.0.0.5 | server |
| 2026-06-10 09:00:45 | INC-001 | `LINUX-SSH-002` | LOW | Accepted SSH Login | root | 10.0.0.5 | server |
| 2026-06-10 09:01:00 | INC-002 | `LINUX-LAT-001` | HIGH | ⚠ SSH Lateral Movement (key-hopping) | jsmith | 10.0.0.9 | server |
| 2026-06-10 09:01:00 | INC-002 | `LINUX-LAT-003` | HIGH | ⚠ Lateral Movement – Multi-Source SSH | jsmith | 10.0.0.11, 10.0.0.9 | unknown |
| 2026-06-10 09:01:00 | INC-002 | `LINUX-SSH-002` | LOW | Accepted SSH Login | jsmith | 10.0.0.9 | server |
| 2026-06-10 09:01:30 | INC-002 | `LINUX-LAT-001` | HIGH | ⚠ SSH Lateral Movement (key-hopping) | jsmith | 10.0.0.11 | server |
| 2026-06-10 09:01:30 | INC-002 | `LINUX-SSH-002` | LOW | Accepted SSH Login | jsmith | 10.0.0.11 | server |
| 2026-06-10 09:02:00 | INC-002 | `LINUX-PRIV-001` | MEDIUM | sudo – Command Executed | jsmith | — | server |
| 2026-06-10 09:02:20 | INC-002 | `LINUX-PRIV-002` | HIGH | sudo – Authentication Failure | jsmith | — | server |
| 2026-06-10 09:03:00 | INC-003 | `LINUX-ACCT-001` | HIGH | New User Created | backdoor | — | server |
| 2026-06-10 09:04:00 | INC-001 | `LINUX-AUTH-001` | HIGH | Root Login | root | — | server |
| 2026-06-10 09:04:00 | INC-001 | `LINUX-SESSION-001` | LOW | Session Opened | root | — | server |
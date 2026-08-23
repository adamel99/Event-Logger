# SOC Log Analyzer Command Cheat Sheet

Use these commands from the project root folder.

## Main Demo Commands

### List supported detection rules

```bash
python3 analyzer.py --list-rules
```

Prints every supported rule ID, log source, Windows Event ID when applicable, severity, MITRE technique, and detection name.

### Analyze the default Linux auth log

```bash
python3 analyzer.py --file sample_logs/auth.log
```

Parses `sample_logs/auth.log`, detects suspicious Linux authentication activity, groups alerts into incidents, prints timelines, evidence, playbook steps, risk scores, and MITRE ATT&CK coverage in the terminal.

### Analyze the Linux auth log with demo config

```bash
python3 analyzer.py --file sample_logs/auth.log --config config/demo_config.json
```

Runs the same Linux analysis, but also loads configurable thresholds, known-good IPs, admin users, and watchlisted accounts from `config/demo_config.json`.

### Export an incident ticket

```bash
python3 analyzer.py --file sample_logs/auth.log --ticket incident-ticket.md
```

Creates `incident-ticket.md` and `incident-ticket.html`. The Markdown file is easy to paste into notes or GitHub, and the HTML file is a browser-friendly analyst ticket with incident summaries, evidence, timelines, playbook steps, risk factors, and MITRE ATT&CK coverage.

### Export HTML and JSON reports

```bash
python3 analyzer.py --file sample_logs/auth.log --html report.html --json report.json
```

Creates `report.html` for a visual dashboard and `report.json` for structured alert, incident, and MITRE summary data.

### Export an investigation timeline

```bash
python3 analyzer.py --file sample_logs/auth.log --timeline timeline.md
```

Creates `timeline.md`, a chronological Markdown timeline with incident ID, rule ID, severity, detection name, user, IP, and host.

### Analyze the Windows sample and export a ticket

```bash
python3 analyzer.py --file sample_logs/windows_security.csv --ticket windows-ticket.md
```

Parses the Windows Event Log CSV sample, detects Windows authentication and lateral movement indicators, then exports `windows-ticket.md` and a browser-friendly `windows-ticket.html`.

## Scenario Demo Commands

### Linux brute force followed by compromise

```bash
python3 analyzer.py --file sample_logs/scenarios/linux_bruteforce_success.auth.log --ticket brute-force-ticket.md
```

Runs a focused scenario where repeated failed root logins are followed by a successful login, privileged activity, and suspicious account creation. Exports the case to `brute-force-ticket.md`.
Also creates `brute-force-ticket.html`.

### Benign admin activity with config context

```bash
python3 analyzer.py --file sample_logs/scenarios/linux_false_positive_admin.auth.log --config config/demo_config.json
```

Runs a scenario that looks noisy but includes known-good admin context from the config file. This is useful for explaining false-positive review and analyst judgment.

### Linux lateral movement and sudo activity

```bash
python3 analyzer.py --file sample_logs/scenarios/linux_lateral_sudo.auth.log --html report.html
```

Runs a focused lateral movement scenario where the same user authenticates from multiple IPs and then performs sudo activity. Exports the visual dashboard to `report.html`.

## Common Options

```bash
--file PATH
```

Required. Points the analyzer at a Linux auth log or Windows Event Log CSV.

```bash
--config PATH
```

Optional. Loads thresholds, known-good IPs, admin users, and watchlist users from a JSON config file.
It can also define expected admin activity so the analyzer can label likely false positives.

```bash
--ticket PATH
```

Optional. Exports a Markdown incident ticket and a matching HTML ticket using the same filename stem.

```bash
--html PATH
```

Optional. Exports a visual HTML dashboard.

```bash
--json PATH
```

Optional. Exports structured JSON containing alerts, incidents, and MITRE summary data.

```bash
--export PATH
```

Optional. Exports individual alerts to CSV.

```bash
--timeline PATH
```

Optional. Exports a chronological investigation timeline to Markdown.

```bash
--severity CRITICAL|HIGH|MEDIUM|LOW
```

Optional. Filters terminal and export output to one severity level.

```bash
--list-rules
```

Optional. Lists supported detection rules and exits. Does not require `--file`.

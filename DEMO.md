# Recruiter Demo Guide

This project demonstrates junior SOC analyst skills through practical log analysis, alert triage, detection logic, MITRE ATT&CK mapping, incident timelines, and analyst-ready reporting.

## Best Five-Minute Demo

1. List the detection catalog.

```bash
python3 analyzer.py --list-rules
```

2. Run the Linux compromise scenario.

```bash
python3 analyzer.py --file sample_logs/scenarios/linux_bruteforce_success.auth.log --ticket brute-force-ticket.md
```

3. Run the Windows lateral movement scenario.

```bash
python3 analyzer.py --file sample_logs/scenarios/windows_psexec_lateral.csv --ticket windows-psexec-ticket.md --html report.html
```

4. Open the generated ticket or dashboard and walk through:

- incident severity, confidence, and risk score
- evidence summary
- timeline
- MITRE ATT&CK techniques
- containment steps
- follow-up searches
- false-positive considerations

## Skills Demonstrated

- Python scripting for defensive security
- Linux authentication log analysis
- Windows Security Event ID analysis
- brute force correlation
- lateral movement detection
- privilege escalation review
- audit log clearing detection
- MITRE ATT&CK mapping
- incident timeline creation
- analyst ticket writing
- false-positive tuning with config context

## Talking Points

- The analyzer groups related alerts into incidents instead of treating every log line as an isolated event.
- Detection rules are documented in `detections/` so the logic is explainable and maintainable.
- Scenario logs in `sample_logs/scenarios/` make the project easy to demo without exposing real logs.
- The ticket export is designed to resemble a SOC triage handoff with evidence, response steps, and validation questions.

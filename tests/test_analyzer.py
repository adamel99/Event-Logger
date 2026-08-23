import json
import os
import tempfile
import unittest

import analyzer


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        analyzer.BRUTE_FORCE_THRESHOLD = 5
        analyzer.BRUTE_FORCE_WINDOW = 60
        analyzer.INCIDENT_WINDOW = 600
        analyzer.LATERAL_TIME_WINDOW = 300
        analyzer.CONFIG["known_good_ips"] = set()
        analyzer.CONFIG["admin_users"] = set()
        analyzer.CONFIG["watchlist_users"] = set()
        analyzer.CONFIG["expected_admin_activity"] = []

    def write_file(self, content, suffix=".log"):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_brute_force_detected_at_threshold(self):
        path = self.write_file(
            "\n".join(
                f"Jun 10 09:00:0{i} server sshd[{i}]: Failed password for root from 10.0.0.5 port 22 ssh2"
                for i in range(1, 6)
            )
        )
        alerts, _ = analyzer.analyze_linux(path)
        self.assertTrue(any(a["detection_id"] == "LINUX-SSH-003" for a in alerts))

    def test_brute_force_not_detected_below_threshold(self):
        path = self.write_file(
            "\n".join(
                f"Jun 10 09:00:0{i} server sshd[{i}]: Failed password for root from 10.0.0.5 port 22 ssh2"
                for i in range(1, 5)
            )
        )
        alerts, _ = analyzer.analyze_linux(path)
        self.assertFalse(any(a["detection_id"] == "LINUX-SSH-003" for a in alerts))

    def test_incident_verdict_for_bruteforce_success(self):
        path = self.write_file(
            "\n".join([
                "Jun 10 09:00:01 server sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2",
                "Jun 10 09:00:03 server sshd[2]: Failed password for root from 10.0.0.5 port 22 ssh2",
                "Jun 10 09:00:05 server sshd[3]: Failed password for root from 10.0.0.5 port 22 ssh2",
                "Jun 10 09:00:07 server sshd[4]: Failed password for root from 10.0.0.5 port 22 ssh2",
                "Jun 10 09:00:09 server sshd[5]: Failed password for root from 10.0.0.5 port 22 ssh2",
                "Jun 10 09:00:45 server sshd[6]: Accepted password for root from 10.0.0.5 port 22 ssh2",
            ])
        )
        alerts, _ = analyzer.analyze_linux(path)
        incidents = analyzer.build_incidents(alerts)
        self.assertEqual(incidents[0]["verdict"], "Likely True Positive")
        self.assertEqual(incidents[0]["confidence"], "High")

    def test_config_expected_admin_activity_marks_likely_false_positive(self):
        path = self.write_file(
            "\n".join([
                "Jun 11 14:10:01 server sshd[20]: Accepted publickey for admin from 10.0.0.20 port 22 ssh2 pts/0",
                "Jun 11 14:10:20 server sudo[21]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update",
            ])
        )
        config_path = self.write_file(
            json.dumps({
                "known_good_ips": ["10.0.0.20"],
                "admin_users": ["admin"],
                "expected_admin_activity": [
                    {
                        "user": "admin",
                        "source_ip": "10.0.0.20",
                        "host": "server",
                        "allowed_commands": ["/usr/bin/apt update"],
                    }
                ],
            }),
            suffix=".json",
        )
        analyzer.load_config(config_path)
        alerts, _ = analyzer.analyze_linux(path)
        incidents = analyzer.build_incidents(alerts)
        self.assertTrue(any(analyzer.triage_context(a)["expected_admin_activity"] for a in alerts))
        self.assertEqual(incidents[0]["verdict"], "Likely False Positive")

    def test_windows_psexec_detection_is_critical(self):
        path = self.write_file(
            '"Id","TimeCreated","Message"\n'
            '"7045","2026-06-10 09:03:00","A service was installed in the system. Account Name: alice Source Network Address: 10.0.0.55 Service Name: PSEXESVC"\n',
            suffix=".csv",
        )
        alerts, _ = analyzer.analyze_windows(path)
        self.assertTrue(any(a["detection_id"] == "WIN-LAT-002" and a["severity"] == "CRITICAL" for a in alerts))

    def test_timeline_export_contains_rule_id_and_host(self):
        path = self.write_file("Jun 10 09:00:45 server sshd[6]: Accepted password for root from 10.0.0.5 port 22 ssh2\n")
        alerts, _ = analyzer.analyze_linux(path)
        incidents = analyzer.build_incidents(alerts)
        out = self.write_file("", suffix=".md")
        analyzer.export_timeline(incidents, path, out)
        with open(out, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("LINUX-SSH-002", content)
        self.assertIn("server", content)

    def test_rule_listing_contains_linux_and_windows_ids(self):
        rules = list(analyzer.iter_detection_rules())
        ids = {rule["id"] for rule in rules}
        self.assertIn("LINUX-SSH-001", ids)
        self.assertIn("WIN-LAT-002", ids)

    def test_config_validation_rejects_bad_threshold(self):
        path = self.write_file(json.dumps({"brute_force_threshold": "five"}), suffix=".json")
        with self.assertRaisesRegex(ValueError, "brute_force_threshold must be an integer"):
            analyzer.load_config(path)

    def test_config_validation_rejects_bad_expected_admin_commands(self):
        path = self.write_file(
            json.dumps({"expected_admin_activity": [{"user": "admin", "allowed_commands": "apt update"}]}),
            suffix=".json",
        )
        with self.assertRaisesRegex(ValueError, "expected_admin_activity\\[0\\].allowed_commands must be a list"):
            analyzer.load_config(path)


if __name__ == "__main__":
    unittest.main()

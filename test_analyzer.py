
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

from analyzer import (
    parse_logs,
    detect_brute_force,
    detect_password_spraying
)
from reporter import export_report


class TestAttackDetection(unittest.TestCase):

    def make_event(self, ip, username, seconds):
        return {
            "ip": ip,
            "username": username,
            "timestamp": datetime(2026, 10, 27, 8, 0, 0)
                         + timedelta(seconds=seconds)
        }

    def test_brute_force_detected(self):
        events = [
            self.make_event("192.168.1.10", "admin", 0),
            self.make_event("192.168.1.10", "admin", 3),
            self.make_event("192.168.1.10", "admin", 6)
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "brute_force")

    def test_no_brute_force(self):
        events = [
            self.make_event("192.168.1.10", "admin", 0),
            self.make_event("192.168.1.10", "admin", 10)
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    def test_password_spraying_detected(self):
        events = [
            self.make_event("192.168.1.20", "admin", 0),
            self.make_event("192.168.1.20", "guest", 30),
            self.make_event("192.168.1.20", "manager", 60)
        ]

        alerts = detect_password_spraying(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["unique_accounts"], 3)

    def test_no_password_spraying(self):
        events = [
            self.make_event("192.168.1.20", "admin", 0),
            self.make_event("192.168.1.20", "guest", 180),
            self.make_event("192.168.1.20", "manager", 360)
        ]

        alerts = detect_password_spraying(events)

        self.assertEqual(len(alerts), 0)

    def test_invalid_user_parsing(self):
        log_line = (
            "Oct 27 08:14:00 ubuntu sshd[1234]: "
            "Failed password for invalid user hacker "
            "from 192.168.56.40 port 52351 ssh2\n"
        )

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False
        ) as file:
            file.write(log_line)
            filename = file.name

        try:
            events = parse_logs(filename)

            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["username"], "hacker")
        finally:
            os.remove(filename)

    def test_repeated_ssh_failures(self):
        log_lines = (
            "2026-11-08T18:32:32+00:00 ubuntu-target sshd[10814]: "
            "Failed password for labuser from 192.168.219.132 port 57658 ssh2\n"
            "2026-11-08T18:32:56+00:00 ubuntu-target sshd[10814]: "
            "message repeated 2 times: [ Failed password for labuser "
            "from 192.168.219.132 port 57658 ssh2]\n"
        )

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False
        ) as file:
            file.write(log_lines)
            filename = file.name

        try:
            events = parse_logs(filename)
            alerts = detect_brute_force(events)

            self.assertEqual(len(events), 3)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["ip"], "192.168.219.132")
        finally:
            os.remove(filename)

    def test_brute_force_exact_window_boundary(self):
        events = [
            self.make_event("192.168.1.10", "admin", 0),
            self.make_event("192.168.1.10", "admin", 30),
            self.make_event("192.168.1.10", "admin", 60)
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["duration"], 60)

    def test_brute_force_outside_window(self):
        events = [
            self.make_event("192.168.1.10", "admin", 0),
            self.make_event("192.168.1.10", "admin", 30),
            self.make_event("192.168.1.10", "admin", 61)
        ]

        self.assertEqual(len(detect_brute_force(events)), 0)

    def test_custom_brute_force_threshold(self):
        events = [
            self.make_event("192.168.1.10", "admin", 0),
            self.make_event("192.168.1.10", "admin", 5),
            self.make_event("192.168.1.10", "admin", 10)
        ]

        self.assertEqual(
            len(detect_brute_force(events, threshold=5)), 0
        )
        self.assertEqual(
            len(detect_brute_force(events, threshold=3)), 1
        )

    def test_spraying_exact_window_boundary(self):
        events = [
            self.make_event("192.168.1.20", "admin", 0),
            self.make_event("192.168.1.20", "guest", 60),
            self.make_event("192.168.1.20", "manager", 120)
        ]

        self.assertEqual(
            len(detect_password_spraying(events)), 1
        )

    def test_spraying_outside_window(self):
        events = [
            self.make_event("192.168.1.20", "admin", 0),
            self.make_event("192.168.1.20", "guest", 60),
            self.make_event("192.168.1.20", "manager", 121)
        ]

        self.assertEqual(
            len(detect_password_spraying(events)), 0
        )

    def test_custom_spraying_threshold(self):
        events = [
            self.make_event("192.168.1.20", "admin", 0),
            self.make_event("192.168.1.20", "guest", 20),
            self.make_event("192.168.1.20", "manager", 40)
        ]

        self.assertEqual(
            len(detect_password_spraying(events, threshold=5)), 0
        )
        self.assertEqual(
            len(detect_password_spraying(events, threshold=3)), 1
        )

    def test_empty_events(self):
        self.assertEqual(detect_brute_force([]), [])
        self.assertEqual(detect_password_spraying([]), [])

    def test_investigation_metadata(self):
        events = [
            self.make_event("192.168.1.10", "admin", 0),
            self.make_event("192.168.1.10", "admin", 5),
            self.make_event("192.168.1.10", "admin", 10)
        ]

        alert = detect_brute_force(events)[0]

        self.assertEqual(alert["severity"], "MEDIUM")
        self.assertEqual(
            alert["first_observed"],
            "2026-10-27T08:00:00Z"
        )
        self.assertEqual(
            alert["last_observed"],
            "2026-10-27T08:00:10Z"
        )
        self.assertTrue(alert["recommended_action"])

    def test_json_report_export(self):
        events = [
            self.make_event("192.168.1.10", "admin", 0),
            self.make_event("192.168.1.10", "admin", 5),
            self.make_event("192.168.1.10", "admin", 10)
        ]

        brute_alerts = detect_brute_force(events)

        with tempfile.TemporaryDirectory() as directory:
            filename = os.path.join(directory, "report.json")

            export_report(
                events,
                brute_alerts,
                [],
                "linux",
                filename
            )

            with open(filename, encoding="utf-8") as file:
                report = json.load(file)

            self.assertEqual(report["total_failed_logins"], 3)
            self.assertEqual(report["summary"]["brute_force_alerts"], 1)
            self.assertEqual(report["summary"]["password_spraying_alerts"], 0)
            self.assertEqual(report["alerts"][0]["severity"], "MEDIUM")
            self.assertIn(
                "recommended_action",
                report["alerts"][0]
            )

    def test_invalid_cli_threshold(self):
        result = subprocess.run(
            [
                sys.executable,
                os.path.join(
                    os.path.dirname(__file__),
                    "analyzer.py"
                ),
                "--file",
                "sample_auth.log",
                "--brute-threshold",
                "0"
            ],
            capture_output=True,
            text=True
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "positive integer",
            result.stderr
        )

    def test_empty_log_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False
        ) as file:
            filename = file.name

        try:
            events = parse_logs(filename)

            self.assertEqual(events, [])
            self.assertEqual(detect_brute_force(events), [])
            self.assertEqual(detect_password_spraying(events), [])
        finally:
            os.remove(filename)


if __name__ == "__main__":
    unittest.main()

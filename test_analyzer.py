
import unittest
import tempfile
import os
from datetime import datetime, timedelta

from analyzer import (
    parse_logs,
    detect_brute_force,
    detect_password_spraying
)


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


if __name__ == "__main__":
    unittest.main()

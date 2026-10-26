
import unittest
from datetime import datetime, timedelta, timezone

from scripts.detect_password_spray import detect_password_spray


class TestPasswordSpray(unittest.TestCase):

    def make_events(self, users, interval=10, ip="203.0.113.50"):
        start = datetime(2026, 10, 26, 9, 0, tzinfo=timezone.utc)

        return [
            {
                "timestamp": start + timedelta(seconds=i * interval),
                "username": username,
                "source_ip": ip,
                "event_type": "FAILURE",
            }
            for i, username in enumerate(users)
        ]

    def test_detects_five_accounts(self):
        events = self.make_events([
            "alice", "bob", "charlie", "david", "emma"
        ])

        alerts = detect_password_spray(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["targeted_accounts"], 5)
        self.assertEqual(
            alerts[0]["rule"], "POSSIBLE_PASSWORD_SPRAY"
        )

    def test_ignores_four_accounts(self):
        events = self.make_events([
            "alice", "bob", "charlie", "david"
        ])

        self.assertEqual(len(detect_password_spray(events)), 0)

    def test_repeated_attempts_same_user(self):
        events = self.make_events(["admin"] * 10)

        self.assertEqual(len(detect_password_spray(events)), 0)

    def test_ignores_slow_attempts(self):
        events = self.make_events(
            ["alice", "bob", "charlie", "david", "emma"],
            interval=120
        )

        self.assertEqual(len(detect_password_spray(events)), 0)

    def test_separate_source_ips(self):
        events = self.make_events(
            ["alice", "bob", "charlie", "david"],
            ip="203.0.113.50"
        )

        events += self.make_events(
            ["emma", "frank", "grace", "henry"],
            ip="203.0.113.51"
        )

        self.assertEqual(len(detect_password_spray(events)), 0)

    def test_out_of_order_events(self):
        events = self.make_events([
            "alice", "bob", "charlie", "david", "emma"
        ])
        events.reverse()

        self.assertEqual(len(detect_password_spray(events)), 1)


if __name__ == "__main__":
    unittest.main()

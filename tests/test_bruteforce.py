
import unittest
from datetime import datetime, timedelta, timezone

from scripts.detect_bruteforce import detect_bruteforce


class TestBruteForceDetection(unittest.TestCase):

    def make_events(self, count, interval=10,
                    username="admin", ip="198.51.100.25"):

        start = datetime(
            2026, 10, 26, 9, 0,
            tzinfo=timezone.utc
        )

        return [
            {
                "timestamp": start + timedelta(
                    seconds=i * interval
                ),
                "username": username,
                "source_ip": ip,
                "event_type": "FAILURE",
            }
            for i in range(count)
        ]

    def test_detects_five_failures(self):
        events = self.make_events(5)

        alerts = detect_bruteforce(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["rule"],
            "POSSIBLE_BRUTE_FORCE"
        )

    def test_ignores_four_failures(self):
        events = self.make_events(4)

        alerts = detect_bruteforce(events)

        self.assertEqual(len(alerts), 0)

    def test_ignores_spread_out_failures(self):
        events = self.make_events(
            5, interval=120
        )

        alerts = detect_bruteforce(events)

        self.assertEqual(len(alerts), 0)

    def test_tracks_ips_separately(self):
        events = self.make_events(
            4, ip="198.51.100.25"
        )

        events += self.make_events(
            4, ip="198.51.100.26"
        )

        alerts = detect_bruteforce(events)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()

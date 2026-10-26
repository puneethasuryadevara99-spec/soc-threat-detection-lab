
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "data" / "authentication_logs.csv"

THRESHOLD = 5
WINDOW = timedelta(seconds=60)


def detect_bruteforce(events):
    # Track recent failures for each username and IP.
    failures = defaultdict(deque)
    alerted = set()
    alerts = []

    # Process events in chronological order.
    events.sort(key=lambda e: e["timestamp"])

    for event in events:
        if event["event_type"] != "FAILURE":
            continue

        key = (event["username"], event["source_ip"])
        timestamp = event["timestamp"]
        recent = failures[key]

        # Add the current failed login.
        recent.append(timestamp)

        # Remove failures older than 60 seconds.
        while recent and timestamp - recent[0] > WINDOW:
            recent.popleft()

        # Generate one alert per username/IP pair.
        if len(recent) >= THRESHOLD and key not in alerted:
            alerts.append({
                "timestamp": timestamp.isoformat(),
                "username": key[0],
                "source_ip": key[1],
                "failed_attempts": len(recent),
                "rule": "POSSIBLE_BRUTE_FORCE",
            })

            alerted.add(key)

    return alerts


def main():
    with INPUT.open(newline="") as file:
        events = list(csv.DictReader(file))

    for event in events:
        event["timestamp"] = datetime.fromisoformat(
            event["timestamp"]
        )

    alerts = detect_bruteforce(events)

    print(f"Events analyzed: {len(events)}")
    print(f"Potential brute-force alerts: {len(alerts)}")

    for alert in alerts:
        print("\nSECURITY ALERT")
        print(f"Rule: {alert['rule']}")
        print(f"Username: {alert['username']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failures in window: {alert['failed_attempts']}")
        print(f"Detected at: {alert['timestamp']}")


if __name__ == "__main__":
    main()

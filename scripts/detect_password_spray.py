
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "data" / "authentication_logs.csv"

THRESHOLD = 5
WINDOW = timedelta(seconds=60)


def detect_password_spray(events):
    # Track failed logins for each source IP.
    failures = defaultdict(deque)
    alerted = set()
    alerts = []

    # Process events chronologically without modifying the input.
    ordered_events = sorted(
        events,
        key=lambda event: event["timestamp"]
    )

    for event in ordered_events:
        if event["event_type"] != "FAILURE":
            continue

        ip = event["source_ip"]
        username = event["username"]
        timestamp = event["timestamp"]

        recent = failures[ip]
        recent.append((timestamp, username))

        # Remove events outside the 60-second window.
        while recent and timestamp - recent[0][0] > WINDOW:
            recent.popleft()

        # Count distinct usernames targeted by this IP.
        unique_users = {user for _, user in recent}

        # Generate one alert per source IP.
        if len(unique_users) >= THRESHOLD and ip not in alerted:
            alerts.append({
                "timestamp": timestamp.isoformat(),
                "source_ip": ip,
                "targeted_accounts": len(unique_users),
                "usernames": sorted(unique_users),
                "rule": "POSSIBLE_PASSWORD_SPRAY",
            })

            alerted.add(ip)

    return alerts


def main():
    with INPUT.open(newline="") as file:
        events = list(csv.DictReader(file))

    for event in events:
        event["timestamp"] = datetime.fromisoformat(
            event["timestamp"]
        )

    alerts = detect_password_spray(events)

    print(f"Events analyzed: {len(events)}")
    print(f"Password spraying alerts: {len(alerts)}")

    for alert in alerts:
        print("\nSECURITY ALERT")
        print(f"Rule: {alert['rule']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Distinct accounts: {alert['targeted_accounts']}")
        print(f"Targeted users: {', '.join(alert['usernames'])}")
        print(f"Detected at: {alert['timestamp']}")


if __name__ == "__main__":
    main()


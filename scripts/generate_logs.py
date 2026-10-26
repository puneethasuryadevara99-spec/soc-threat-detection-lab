
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Project directory
ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "data" / "authentication_logs.csv"

# Simulated authentication events.
# These are synthetic records, not real user activity.
events = [
    ("alice", "192.0.2.10", "SUCCESS"),
    ("bob", "192.0.2.11", "SUCCESS"),
    ("charlie", "192.0.2.12", "FAILURE"),
    ("charlie", "192.0.2.12", "SUCCESS"),
    ("david", "192.0.2.13", "SUCCESS"),
]

# Simulate repeated failed logins against one account.
for _ in range(12):
    events.append(
        ("admin", "198.51.100.25", "FAILURE")
    )

# Simulate a successful login after the failures.
events.append(
    ("admin", "198.51.100.25", "SUCCESS")
)

# Simulate password spraying across multiple accounts.
# One source IP attempts a login to six different users.
spray_source = "203.0.113.50"

spray_targets = [
    "alice",
    "bob",
    "charlie",
    "david",
    "emma",
    "frank",
]

for username in spray_targets:
    events.append(
        (username, spray_source, "FAILURE")
    )


start = datetime(
    2026, 10, 26, 9, 0, 0,
    tzinfo=timezone.utc
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", newline="") as file:
    writer = csv.writer(file, lineterminator="\n")

    writer.writerow([
        "timestamp",
        "username",
        "source_ip",
        "event_type",
    ])

    for index, (username, ip, event) in enumerate(events):
        timestamp = start + timedelta(seconds=index * 10)

        writer.writerow([
            timestamp.isoformat(),
            username,
            ip,
            event,
        ])

print(f"Generated {len(events)} authentication events")
print(f"Saved to: {OUTPUT}")

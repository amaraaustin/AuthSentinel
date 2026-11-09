
import csv
from datetime import datetime, timezone


def parse_windows_logs(filename):
    events = []

    with open(filename, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        for row in reader:
            if row["EventID"].strip() != "4625":
                continue

            ip = row["IpAddress"].strip()
            username = row["TargetUserName"].strip()
            timestamp = datetime.fromisoformat(
                row["TimeCreated"].strip().replace("Z", "+00:00")
            )

            if timestamp.tzinfo is not None:
                timestamp = timestamp.astimezone(
                    timezone.utc
                ).replace(tzinfo=None)

            if not ip or ip == "-" or not username or username == "-":
                continue

            events.append({
                "ip": ip,
                "username": username,
                "timestamp": timestamp
            })

    return events


import csv
from datetime import datetime, timezone


def parse_windows_logs(filename):
    events = []

    with open(filename, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        required_columns = {
            "EventID",
            "TimeCreated",
            "IpAddress",
            "TargetUserName"
        }

        if not reader.fieldnames or not required_columns.issubset(
            reader.fieldnames
        ):
            raise ValueError(
                "Windows CSV is missing required columns"
            )

        for row in reader:
            try:
                event_id = (row["EventID"] or "").strip()

                if event_id != "4625":
                    continue

                ip = (row["IpAddress"] or "").strip()
                username = (row["TargetUserName"] or "").strip()
                timestamp_text = (row["TimeCreated"] or "").strip()

                if not ip or ip == "-" or not username or username == "-":
                    continue

                timestamp = datetime.fromisoformat(
                    timestamp_text.replace("Z", "+00:00")
                )

                if timestamp.tzinfo is not None:
                    timestamp = timestamp.astimezone(
                        timezone.utc
                    ).replace(tzinfo=None)

                events.append({
                    "ip": ip,
                    "username": username,
                    "timestamp": timestamp
                })

            except (ValueError, TypeError, AttributeError):
                continue

    return events

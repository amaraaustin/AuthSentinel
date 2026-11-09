
import argparse
import re
from datetime import datetime, timedelta, timezone

from reporter import export_report

ATTEMPT_THRESHOLD = 3
TIME_WINDOW_SECONDS = 60
SPRAY_USER_THRESHOLD = 3
SPRAY_WINDOW_SECONDS = 120


def parse_logs(log_file):
    events = []

    with open(log_file, "r") as file:
        for line in file:
            if "Failed password" not in line or "sshd[" not in line:
                continue

            words = line.split()

            ip_address = words[words.index("from") + 1]
            username_position = words.index("for") + 1

            if words[username_position] == "invalid":
                username = words[username_position + 2]
            else:
                username = words[username_position]

            if words[0][:4].isdigit() and "T" in words[0]:
                login_time = datetime.fromisoformat(
                    words[0].replace("Z", "+00:00")
                )

                if login_time.tzinfo is not None:
                    login_time = login_time.astimezone(
                        timezone.utc
                    ).replace(tzinfo=None)
            else:
                timestamp = "2026 " + " ".join(words[:3])
                login_time = datetime.strptime(
                    timestamp, "%Y %b %d %H:%M:%S"
                )

            repeated = re.search(
                r"message repeated (\d+) times:",
                line
            )

            count = int(repeated.group(1)) if repeated else 1

            for _ in range(count):
                events.append({
                    "ip": ip_address,
                    "username": username,
                    "timestamp": login_time
                })

    return events


def detect_brute_force(events):
    failed_attempts = {}
    alerts = []

    for event in events:
        key = (event["ip"], event["username"])

        if key not in failed_attempts:
            failed_attempts[key] = []

        failed_attempts[key].append(event["timestamp"])

    for (ip, username), times in failed_attempts.items():
        times.sort()

        for i in range(len(times) - ATTEMPT_THRESHOLD + 1):
            first_attempt = times[i]
            last_attempt = times[i + ATTEMPT_THRESHOLD - 1]
            difference = last_attempt - first_attempt

            if difference <= timedelta(seconds=TIME_WINDOW_SECONDS):
                alerts.append({
                    "type": "brute_force",
                    "ip": ip,
                    "username": username,
                    "attempts": ATTEMPT_THRESHOLD,
                    "duration": difference.total_seconds()
                })
                break

    return alerts


def detect_password_spraying(events):
    spray_attempts = {}
    alerts = []

    for event in events:
        ip = event["ip"]

        if ip not in spray_attempts:
            spray_attempts[ip] = []

        spray_attempts[ip].append((
            event["timestamp"],
            event["username"]
        ))

    for ip, attempts in spray_attempts.items():
        attempts.sort()

        for start in range(len(attempts)):
            start_time = attempts[start][0]
            usernames = set()

            for login_time, username in attempts[start:]:
                if login_time - start_time > timedelta(
                    seconds=SPRAY_WINDOW_SECONDS
                ):
                    break

                usernames.add(username)

                if len(usernames) >= SPRAY_USER_THRESHOLD:
                    alerts.append({
                        "type": "password_spraying",
                        "ip": ip,
                        "unique_accounts": len(usernames),
                        "usernames": sorted(usernames)
                    })
                    break

            if any(alert["ip"] == ip for alert in alerts):
                break

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Linux and Windows authentication logs"
    )

    parser.add_argument(
        "--file",
        required=True,
        help="Path to the authentication log file"
    )

    parser.add_argument(
        "--format",
        choices=["linux", "windows"],
        default="linux",
        help="Authentication log format"
    )

    parser.add_argument(
        "--output",
        help="Save the security report as a JSON file"
    )

    args = parser.parse_args()

    try:
        if args.format == "windows":
            from windows_parser import parse_windows_logs
            events = parse_windows_logs(args.file)
        else:
            events = parse_logs(args.file)
    except (FileNotFoundError, PermissionError, ValueError, KeyError) as error:
        parser.error(str(error))

    brute_force_alerts = detect_brute_force(events)
    spraying_alerts = detect_password_spraying(events)

    print("ATTACK-AND-DETECT SECURITY REPORT")
    print("---------------------------------")
    print(f"Log format: {args.format}")
    print(f"Failed authentication events: {len(events)}")

    print("\nBRUTE-FORCE DETECTION")
    print("---------------------")

    if not brute_force_alerts:
        print("No brute-force alerts detected.")

    for alert in brute_force_alerts:
        print("ALERT: Possible brute-force attack")
        print(f"Source IP: {alert['ip']}")
        print(f"Target account: {alert['username']}")
        print(f"Failed attempts: {alert['attempts']}")
        print(f"Duration: {alert['duration']} seconds")

    print("\nPASSWORD SPRAYING DETECTION")
    print("---------------------------")

    if not spraying_alerts:
        print("No password-spraying alerts detected.")

    for alert in spraying_alerts:
        print("ALERT: Possible password spraying")
        print(f"Source IP: {alert['ip']}")
        print(f"Unique accounts: {alert['unique_accounts']}")
        print(f"Usernames: {', '.join(alert['usernames'])}")

    if args.output:
        try:
            export_report(
                events,
                brute_force_alerts,
                spraying_alerts,
                args.format,
                args.output
            )
        except (OSError, TypeError, ValueError) as error:
            parser.error(str(error))

        print(f"\nJSON report saved to: {args.output}")


if __name__ == "__main__":
    main()

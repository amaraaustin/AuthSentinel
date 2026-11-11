
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

            try:
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
                    timestamp = (
                        f"{datetime.now().year} "
                        + " ".join(words[:3])
                    )
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

            except (ValueError, IndexError, TypeError):
                continue

    return events


def detect_brute_force(
    events,
    threshold=ATTEMPT_THRESHOLD,
    window_seconds=TIME_WINDOW_SECONDS
):
    failed_attempts = {}
    alerts = []

    for event in events:
        key = (event["ip"], event["username"])
        failed_attempts.setdefault(key, []).append(
            event["timestamp"]
        )

    for (ip, username), times in failed_attempts.items():
        times.sort()

        for i in range(len(times) - threshold + 1):
            first_attempt = times[i]
            last_attempt = times[i + threshold - 1]
            difference = last_attempt - first_attempt

            if difference <= timedelta(seconds=window_seconds):
                alerts.append({
                    "type": "brute_force",
                    "severity": "MEDIUM",
                    "ip": ip,
                    "username": username,
                    "attempts": threshold,
                    "duration": difference.total_seconds(),
                    "first_observed": first_attempt.isoformat() + "Z",
                    "last_observed": last_attempt.isoformat() + "Z",
                    "recommended_action": (
                        "Review authentication activity from this IP, "
                        "check for subsequent successful logins, and "
                        "investigate the targeted account."
                    )
                })
                break

    return alerts


def detect_password_spraying(
    events,
    threshold=SPRAY_USER_THRESHOLD,
    window_seconds=SPRAY_WINDOW_SECONDS
):
    spray_attempts = {}
    alerts = []

    for event in events:
        spray_attempts.setdefault(
            event["ip"], []
        ).append((
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
                    seconds=window_seconds
                ):
                    break

                usernames.add(username)

                if len(usernames) >= threshold:
                    alerts.append({
                        "type": "password_spraying",
                        "severity": "MEDIUM",
                        "ip": ip,
                        "unique_accounts": len(usernames),
                        "usernames": sorted(usernames),
                        "first_observed": start_time.isoformat() + "Z",
                        "last_observed": login_time.isoformat() + "Z",
                        "recommended_action": (
                            "Investigate authentication attempts across "
                            "the targeted accounts, review successful "
                            "logins, and assess the source IP."
                        )
                    })
                    break

            if any(alert["ip"] == ip for alert in alerts):
                break

    return alerts


def positive_integer(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Value must be a positive integer"
        )

    if number < 1:
        raise argparse.ArgumentTypeError(
            "Value must be a positive integer"
        )

    return number


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

    parser.add_argument(
        "--brute-threshold",
        type=positive_integer,
        default=ATTEMPT_THRESHOLD,
        help="Failed attempts required for brute-force detection"
    )

    parser.add_argument(
        "--brute-window",
        type=positive_integer,
        default=TIME_WINDOW_SECONDS,
        help="Brute-force detection window in seconds"
    )

    parser.add_argument(
        "--spray-threshold",
        type=positive_integer,
        default=SPRAY_USER_THRESHOLD,
        help="Unique accounts required for password spraying"
    )

    parser.add_argument(
        "--spray-window",
        type=positive_integer,
        default=SPRAY_WINDOW_SECONDS,
        help="Password-spraying detection window in seconds"
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

    brute_force_alerts = detect_brute_force(
        events,
        threshold=args.brute_threshold,
        window_seconds=args.brute_window
    )

    spraying_alerts = detect_password_spraying(
        events,
        threshold=args.spray_threshold,
        window_seconds=args.spray_window
    )

    print("AUTHSENTINEL SECURITY REPORT")
    print("---------------------------------")
    print(f"Log format: {args.format}")
    print(f"Failed authentication events: {len(events)}")
    print(f"Brute-force threshold: {args.brute_threshold}")
    print(f"Brute-force window: {args.brute_window} seconds")
    print(f"Spraying threshold: {args.spray_threshold}")
    print(f"Spraying window: {args.spray_window} seconds")

    print("\nBRUTE-FORCE DETECTION")
    print("---------------------")

    if not brute_force_alerts:
        print("No brute-force alerts detected.")

    for alert in brute_force_alerts:
        print("\nALERT: Possible brute-force attack")
        print(f"Severity: {alert['severity']}")
        print(f"Source IP: {alert['ip']}")
        print(f"Target account: {alert['username']}")
        print(f"Failed attempts: {alert['attempts']}")
        print(f"Duration: {alert['duration']} seconds")
        print(f"First observed: {alert['first_observed']}")
        print(f"Last observed: {alert['last_observed']}")
        print(f"Recommended action: {alert['recommended_action']}")

    print("\nPASSWORD SPRAYING DETECTION")
    print("---------------------------")

    if not spraying_alerts:
        print("No password-spraying alerts detected.")

    for alert in spraying_alerts:
        print("\nALERT: Possible password spraying")
        print(f"Severity: {alert['severity']}")
        print(f"Source IP: {alert['ip']}")
        print(f"Unique accounts: {alert['unique_accounts']}")
        print(f"Usernames: {', '.join(alert['usernames'])}")
        print(f"First observed: {alert['first_observed']}")
        print(f"Last observed: {alert['last_observed']}")
        print(f"Recommended action: {alert['recommended_action']}")

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

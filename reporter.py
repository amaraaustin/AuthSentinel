
import json
from datetime import datetime, timezone


def export_report(events, brute_force_alerts, spraying_alerts, log_format, filename):
    report = {
        "tool": "Attack-and-Detect",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_format": log_format,
        "total_failed_logins": len(events),
        "summary": {
            "brute_force_alerts": len(brute_force_alerts),
            "password_spraying_alerts": len(spraying_alerts)
        },
        "alerts": brute_force_alerts + spraying_alerts
    }

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report

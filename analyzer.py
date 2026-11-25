import re
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import csv

LOG_FILE = Path("logs/auth.log")

PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>\S+) sshd\[\d+\]: "
    r"(?P<status>Failed|Accepted) password for "
    r"(?:invalid user )?(?P<username>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)


def parse_log(line):
    match = PATTERN.search(line)

    if match:
        return match.groupdict()

    return None


def detect_failed_logins(events):
    failed_attempts = defaultdict(deque)
    alerts = []

    threshold = 5
    time_window = timedelta(seconds=60)

    for event in events:
        timestamp = datetime.strptime(
            "2026 " + event["timestamp"],
            "%Y %b %d %H:%M:%S"
        )

        key = (
            event["ip"],
            event["username"],
            event["hostname"]
        )

        attempts = failed_attempts[key]

        # Remove attempts outside the detection window
        while attempts and timestamp - attempts[0] > time_window:
            attempts.popleft()

        if event["status"] == "Failed":

            attempts.append(timestamp)

            if len(attempts) == threshold:
                alerts.append({
                    "timestamp": str(timestamp),
                    "source_ip": event["ip"],
                    "username": event["username"],
                    "hostname": event["hostname"],
                    "failed_attempts": len(attempts),
                    "time_window": 60,
                    "severity": "MEDIUM",
                    "description": "Possible brute-force activity"
                })

        elif event["status"] == "Accepted":

            if len(attempts) >= threshold:
                alerts.append({
                    "timestamp": str(timestamp),
                    "source_ip": event["ip"],
                    "username": event["username"],
                    "hostname": event["hostname"],
                    "failed_attempts": len(attempts),
                    "time_window": 60,
                    "severity": "HIGH",
                    "description": "Successful login after repeated failures"
                })

            # Reset failed attempts after successful authentication
            attempts.clear()

    return alerts


RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
RESET = "\033[0m"

def export_alerts(alerts):
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # Export alerts to JSON
    json_file = output_dir / "alerts.json"

    with json_file.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    # Export alerts to CSV
    csv_file = output_dir / "alerts.csv"

    fields = [
        "timestamp",
        "source_ip",
        "username",
        "hostname",
        "failed_attempts",
        "time_window",
        "severity",
        "description"
    ]

    with csv_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"\n{GREEN}[INFO]{RESET} Alerts exported to:")
    print(f"  {json_file}")
    print(f"  {csv_file}")

events = []

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        event = parse_log(line)

        if event:
            events.append(event)

alerts = detect_failed_logins(events)

print(f"\n{CYAN}{BOLD}{'=' * 60}")
print("             PYTHON SECURITY LOG ANALYZER")
print(f"{'=' * 60}{RESET}")

print(f"\n{GREEN}[INFO]{RESET} Total events analyzed: {len(events)}")
print(f"{GREEN}[INFO]{RESET} Security alerts generated: {len(alerts)}")

for alert in alerts:

    if alert["severity"] == "HIGH":
        color = RED
    elif alert["severity"] == "MEDIUM":
        color = YELLOW
    else:
        color = GREEN

    print(f"\n{color}{BOLD}[{alert['severity']} SECURITY ALERT]{RESET}")
    print(f"{color}{'-' * 60}{RESET}")

    for key, value in alert.items():
        if key == "severity":
            continue

        label = key.replace("_", " ").title()
        print(f"{label:<20}: {value}")

    print(f"{color}{'-' * 60}{RESET}")

print(f"\n{GREEN}[INFO] Analysis completed successfully.{RESET}")

export_alerts(alerts)
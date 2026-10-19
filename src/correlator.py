from datetime import datetime
from pathlib import Path
import pwd

from audit_parser import parse_audit_log
from event_store import get_recent_events

MAX_TIME_DIFFERENCE = 5.0


def get_username(uid):
    """Translate a numeric user ID into a username."""
    if uid is None:
        return "unknown"

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid:{uid}"


def correlate_events(limit=100):
    """Match SQLite filesystem events with audit records."""
    sqlite_events = get_recent_events(limit)
    audit_events = parse_audit_log()

    # Only use audit records associated with file changes.
    change_events = [
        event for event in audit_events
        if event.get("key") == "org_file_changes"
        and event.get("success") == "yes"
    ]

    results = []

    for db_event in sqlite_events:
        event_id, timestamp, event_type, file_path, details = db_event

        # Ignore manual test records and unrelated paths.
        if event_type not in {
            "CREATED", "MODIFIED", "DELETED", "PERMISSION_CHANGED"
        }:
            continue

        if not file_path.startswith("/opt/organization/"):
            continue

        # SQLite uses local time; auditd uses Unix timestamps.
        sqlite_time = datetime.strptime(
            timestamp, "%Y-%m-%d %H:%M:%S"
        ).timestamp()

        candidates = []

        for audit_event in change_events:
            # Match the exact file path, not its parent directory.
            if file_path not in audit_event.get("paths", []):
                continue

            difference = abs(
                sqlite_time - audit_event["timestamp"]
            )

            if difference <= MAX_TIME_DIFFERENCE:
                candidates.append((difference, audit_event))

        if not candidates:
            results.append({
                "sqlite_id": event_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "file_path": file_path,
                "details": details,
                "matched": False,
            })
            continue

        # Select the closest audit record in time.
        candidates.sort(key=lambda item: item[0])
        difference, audit_event = candidates[0]

        results.append({
            "sqlite_id": event_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "file_path": file_path,
            "details": details,
            "matched": True,
            "time_difference_seconds": round(difference, 3),
            "audit_event_id": audit_event["event_id"],
            "username": get_username(audit_event.get("euid")),
            "uid": audit_event.get("euid"),
            "auid": audit_event.get("auid"),
            "pid": audit_event.get("pid"),
            "process": audit_event.get("comm"),
            "executable": audit_event.get("exe"),
            "success": audit_event.get("success"),
        })

    return results


if __name__ == "__main__":
    for event in correlate_events():
        print("-" * 60)
        print(f"SQLite event: {event['sqlite_id']}")
        print(f"Type:         {event['event_type']}")
        print(f"File:         {event['file_path']}")

        if event["matched"]:
            print("Correlation:  MATCHED")
            print(f"Audit ID:     {event['audit_event_id']}")
            print(f"User:         {event['username']}")
            print(f"UID:          {event['uid']}")
            print(f"Login AUID:   {event['auid']}")
            print(f"PID:          {event['pid']}")
            print(f"Process:      {event['process']}")
            print(f"Executable:   {event['executable']}")
            print(
                "Time delta:   "
                f"{event['time_difference_seconds']} seconds"
            )
        else:
            print("Correlation:  NO MATCH")
            print("User/process: Unknown from matched audit evidence")

        if event.get("details"):
            print(f"Details:      {event['details']}")

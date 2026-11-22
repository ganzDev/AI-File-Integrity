import os
from datetime import datetime
import pwd

from audit_parser import parse_audit_log
from event_store import get_recent_events


MAX_TIME_DIFFERENCE = 5.0

# Linux x86_64 syscall numbers.
OPEN_SYSCALLS = {2, 257}
DELETE_SYSCALLS = {87, 263}
PERMISSION_SYSCALLS = {90, 91, 268, 452}

SUPPORTED_EVENTS = {
    "CREATED",
    "MODIFIED",
    "DELETED",
    "PERMISSION_CHANGED",
}

WATCH_DIRECTORY = "/opt/organization/"


def get_username(uid):
    """Translate a numeric user ID into a username."""
    if uid is None:
        return "unknown"

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return f"uid:{uid}"


def get_audit_operation(audit_event):
    """
    Classify an audit record using its syscall and flags.

    A successful file-creation open can also modify file content.
    """
    syscall = audit_event.get("syscall")
    flags = audit_event.get("open_flags")
    access_mode = audit_event.get("access_mode")

    if audit_event.get("success") != "yes":
        return None

    if syscall in DELETE_SYSCALLS:
        return "DELETED"

    if syscall in PERMISSION_SYSCALLS:
        return "PERMISSION_CHANGED"

    if syscall in OPEN_SYSCALLS:
        if flags is None:
            return None

        if flags & os.O_CREAT:
            return "CREATED"

        if access_mode in ("WRITE", "READ_WRITE"):
            return "MODIFIED"

    return None


def operations_match(event_type, audit_event):
    """
    Determine whether an audit operation is compatible with
    the filesystem event reported by Watchdog.
    """
    operation = get_audit_operation(audit_event)

    if event_type == "CREATED":
        return operation == "CREATED"

    if event_type == "MODIFIED":
        # A file can be modified during its initial creation.
        return operation in {"CREATED", "MODIFIED"}

    if event_type == "DELETED":
        return operation == "DELETED"

    if event_type == "PERMISSION_CHANGED":
        return operation == "PERMISSION_CHANGED"

    return False


def candidate_priority(event_type, audit_event):
    """
    Prefer an established-file write for MODIFIED events
    when audit records have equally close timestamps.
    """
    operation = get_audit_operation(audit_event)

    if event_type == "MODIFIED":
        if operation == "MODIFIED":
            return 0

        if operation == "CREATED":
            return 1

    return 0


def correlate_events(limit=100, sqlite_events=None, audit_events=None):
    """
    Match SQLite filesystem events with compatible audit records.

    Correlation requires:
      1. An exact file path.
      2. A compatible filesystem operation.
      3. A timestamp within the configured window.
      4. A successful audit syscall.
    """
    if sqlite_events is None:
        sqlite_events = get_recent_events(limit)
    if audit_events is None:
        audit_events = parse_audit_log()

    # Only use successful audit records for file changes.
    change_events = [
        event
        for event in audit_events
        if event.get("key") == "org_file_changes"
        and event.get("success") == "yes"
        and get_audit_operation(event) is not None
    ]

    # Index by path so processing a batch does not scan every audit
    # operation for each Watchdog notification.
    audit_by_path = {}
    for audit_event in change_events:
        for path in set(audit_event.get("paths", [])):
            audit_by_path.setdefault(path, []).append(audit_event)

    results = []

    for db_event in sqlite_events:
        event_id, timestamp, event_type, file_path, details = db_event

        if event_type not in SUPPORTED_EVENTS:
            continue

        if not file_path.startswith(WATCH_DIRECTORY):
            continue

        sqlite_time = datetime.strptime(
            timestamp, "%Y-%m-%d %H:%M:%S"
        ).timestamp()

        candidates = []

        for audit_event in audit_by_path.get(file_path, []):

            # Reject unrelated operations.
            if not operations_match(event_type, audit_event):
                continue

            difference = abs(
                sqlite_time - audit_event["timestamp"]
            )

            if difference > MAX_TIME_DIFFERENCE:
                continue

            priority = candidate_priority(event_type, audit_event)

            candidates.append((
                difference,
                priority,
                audit_event,
            ))

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

        # Prefer the closest compatible operation.
        # Resolve equal-time matches using operation specificity.
        candidates.sort(
            key=lambda item: (item[0], item[1])
        )

        difference, _, audit_event = candidates[0]

        results.append({
            "sqlite_id": event_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "file_path": file_path,
            "details": details,
            "matched": True,
            "time_difference_seconds": round(difference, 3),
            "audit_event_id": audit_event["event_id"],
            "audit_timestamp": audit_event["timestamp"],
            "audit_operation": get_audit_operation(audit_event),
            "username": get_username(audit_event.get("euid")),
            "uid": audit_event.get("euid"),
            "auid": audit_event.get("auid"),
            "pid": audit_event.get("pid"),
            "process": audit_event.get("comm"),
            "executable": audit_event.get("exe"),
            "success": audit_event.get("success"),
        })

    return results


def group_related_audit_events(
    reference_event_id,
    reference_timestamp,
    window_seconds=5,
    min_events=2,
):
    """
    Find audit events belonging to the same behavioral incident.

    Events must share:
    - Effective user (EUID)
    - Historical process ID (PID)
    - Parent directory
    - Operation type
    - A bounded time window

    Uses auditd evidence, not Watchdog notification counts.
    """
    from datetime import datetime
    from pathlib import Path

    from audit_parser import parse_audit_log

    if isinstance(reference_timestamp, str):
        reference_time = datetime.strptime(
            reference_timestamp[:19],
            "%Y-%m-%d %H:%M:%S",
        ).timestamp()
    else:
        reference_time = float(reference_timestamp)

    window_seconds = max(1, min(int(window_seconds), 300))
    min_events = max(2, int(min_events))

    audit_events = parse_audit_log()

    # Audit IDs can repeat across boots. Match both ID and time.
    candidates = [
        event
        for event in audit_events
        if str(event.get("event_id")) == str(reference_event_id)
        and event.get("syscall") is not None
        and event.get("timestamp") is not None
        and abs(event["timestamp"] - reference_time) <= 10
    ]

    if len(candidates) != 1:
        return {
            "status": "REFERENCE_NOT_UNIQUE",
            "matching_records": len(candidates),
            "events": [],
        }

    reference = candidates[0]

    reference_paths = [
        path
        for path in reference.get("paths", [])
        if path.startswith("/opt/organization/")
    ]

    if not reference_paths:
        return {
            "status": "NO_MONITORED_PATH",
            "events": [],
        }

    reference_path = reference_paths[-1]
    directory = str(Path(reference_path).parent)

    operation = get_audit_operation(reference)

    if operation is None:
        return {
            "status": "UNSUPPORTED_OPERATION",
            "events": [],
        }

    related = []
    seen = set()

    for event in audit_events:
        if event.get("syscall") is None:
            continue

        if event.get("success") != "yes":
            continue

        if get_audit_operation(event) != operation:
            continue

        if event.get("euid") != reference.get("euid"):
            continue

        if event.get("pid") != reference.get("pid"):
            continue

        timestamp = event.get("timestamp")

        if timestamp is None:
            continue

        if abs(timestamp - reference["timestamp"]) > window_seconds:
            continue

        for path in event.get("paths", []):
            if not path.startswith("/opt/organization/"):
                continue

            if str(Path(path).parent) != directory:
                continue

            identity = (
                event.get("event_id"),
                timestamp,
                path,
            )

            if identity in seen:
                continue

            seen.add(identity)

            related.append({
                "audit_event_id": str(event["event_id"]),
                "timestamp": timestamp,
                "operation": get_audit_operation(event),
                "file_path": path,
                "pid": event["pid"],
                "euid": event["euid"],
                "process": event.get("comm"),
            })

    related.sort(
        key=lambda event: (
            event["timestamp"],
            int(event["audit_event_id"]),
        )
    )

    unique_files = {
        event["file_path"] for event in related
    }

    timestamps = [
        event["timestamp"] for event in related
    ]

    duration = (
        max(timestamps) - min(timestamps)
        if timestamps else 0.0
    )

    # Describe behavior without assuming O_CREAT caused creation.
    behavior = operation

    if operation == "CREATED":
        behavior = "REPEATED_WRITE_OPENS"

    return {
        "status": (
            "GROUP_DETECTED"
            if len(related) >= min_events
            else "SINGLE_EVENT"
        ),
        "operation": operation,
        "directory": directory,
        "pid": reference.get("pid"),
        "euid": reference.get("euid"),
        "process": reference.get("comm"),
        "event_count": len(related),
        "unique_file_count": len(unique_files),
        "duration_seconds": round(duration, 4),
        "events": related,
        "behavior": behavior,
    }


if __name__ == "__main__":
    for event in correlate_events():
        print("-" * 60)
        print(f"SQLite event: {event['sqlite_id']}")
        print(f"Type:         {event['event_type']}")
        print(f"File:         {event['file_path']}")

        if event["matched"]:
            print("Correlation:  MATCHED")
            print(f"Audit ID:     {event['audit_event_id']}")
            print(f"Audit op:     {event['audit_operation']}")
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

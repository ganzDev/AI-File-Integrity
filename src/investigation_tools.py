
"""Read-only evidence retrieval tools for the AI investigator."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

import psutil

from audit_parser import parse_audit_log
from correlator import get_username
from event_store import DATABASE_PATH


WATCH_DIRECTORY = Path("/opt/organization")
MAX_RESULTS = 50


def database_connection():
    """Open the existing SQLite database in read-only mode."""
    database = DATABASE_PATH.resolve()

    if not database.is_file():
        raise FileNotFoundError(
            f"Security database does not exist: {database}"
        )

    connection = sqlite3.connect(
        database.as_uri() + "?mode=ro",
        uri=True,
    )
    connection.row_factory = sqlite3.Row

    return connection


def get_finding(finding_id):
    """Retrieve one persisted security finding by its database ID."""
    with database_connection() as connection:
        row = connection.execute(
            "SELECT * FROM findings WHERE id = ?",
            (int(finding_id),),
        ).fetchone()

    return dict(row) if row else {
        "error": "Finding not found",
        "finding_id": finding_id,
    }


def get_file_history(file_path, limit=20):
    """Retrieve recent filesystem events for one monitored path."""
    path = Path(file_path)

    if not path.is_absolute():
        return {"error": "An absolute file path is required"}

    if not path.is_relative_to(WATCH_DIRECTORY):
        return {"error": "Path is outside the monitored directory"}

    limit = max(1, min(int(limit), MAX_RESULTS))

    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, timestamp, event_type, file_path, details
            FROM events
            WHERE file_path = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (str(path), limit),
        ).fetchall()

    return {
        "file_path": str(path),
        "events": [dict(row) for row in rows],
    }


def get_audit_evidence(audit_event_id, timestamp=None):
    """
    Retrieve a specific audit event with syscall and process details.

    An optional finding timestamp helps distinguish audit IDs reused
    after an audit log rotation or system restart.
    """
    event_id = str(audit_event_id)
    events = [
        event for event in parse_audit_log()
        if event.get("event_id") == event_id
        and event.get("syscall") is not None
    ]

    if timestamp is not None:
        reference_time = datetime.strptime(
            timestamp[:19], "%Y-%m-%d %H:%M:%S"
        ).timestamp()

        events = [
            event for event in events
            if abs(event["timestamp"] - reference_time) <= 10
        ]

    return {
        "audit_event_id": event_id,
        "events": events[:MAX_RESULTS],
        "total_matches": len(events),
    }


def get_related_audit_activity(
    audit_event_id,
    timestamp,
    window_seconds=15,
    limit=30,
):
    """
    Find activity near an audit event involving the same user.

    This can reveal bursts of file activity that separate detector
    findings do not recognize as a related pattern.
    """
    window_seconds = max(1, min(int(window_seconds), 300))
    limit = max(1, min(int(limit), MAX_RESULTS))

    reference_time = datetime.strptime(
        timestamp[:19], "%Y-%m-%d %H:%M:%S"
    ).timestamp()

    events = parse_audit_log()

    target = next(
        (
            event for event in events
            if event.get("event_id") == str(audit_event_id)
            and event.get("euid") is not None
            and abs(event["timestamp"] - reference_time) <= 10
        ),
        None,
    )

    if target is None:
        return {"error": "Reference audit event not found"}

    uid = target["euid"]
    related = []

    for event in events:
        if event.get("euid") != uid:
            continue

        if event.get("syscall") is None:
            continue

        if abs(event["timestamp"] - target["timestamp"]) > window_seconds:
            continue

        paths = [
            path for path in event.get("paths", [])
            if path.startswith("/opt/organization/")
        ]

        if not paths:
            continue

        related.append({
            "event_id": event["event_id"],
            "timestamp": event["timestamp"],
            "syscall": event.get("syscall"),
            "operation": event.get("operation"),
            "access_mode": event.get("access_mode"),
            "permission_mode": event.get("permission_mode"),
            "success": event.get("success"),
            "pid": event.get("pid"),
            "process": event.get("comm"),
            "paths": paths,
        })

    related.sort(
        key=lambda event: abs(
            event["timestamp"] - target["timestamp"]
        )
    )

    return {
        "username": get_username(uid),
        "reference_event_id": str(audit_event_id),
        "window_seconds": window_seconds,
        "total_matches": len(related),
        "events": related[:limit],
    }


def get_live_process(pid):
    """
    Retrieve live process information when available.

    Historical audit evidence remains authoritative for exited
    processes; a PID can be reused by the operating system.
    """
    try:
        process = psutil.Process(int(pid))

        with process.oneshot():
            return {
                "pid": process.pid,
                "name": process.name(),
                "executable": process.exe(),
                "username": process.username(),
                "status": process.status(),
                "created_at": process.create_time(),
                "note": (
                    "Live process only. Verify creation time "
                    "before associating it with historical events."
                ),
            }

    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return {
            "pid": pid,
            "running": False,
            "note": "Process is no longer running.",
        }

    except (psutil.AccessDenied, PermissionError):
        return {
            "pid": pid,
            "error": "Insufficient permission to inspect process",
        }


if __name__ == "__main__":
    finding = get_finding(1702)

    print("FINDING:")
    print(json.dumps(finding, indent=2))

    if "error" not in finding:
        print("\nFILE HISTORY:")
        print(json.dumps(
            get_file_history(finding["file_path"]),
            indent=2,
        ))

        if finding.get("audit_event_id"):
            print("\nAUDIT EVIDENCE:")
            print(json.dumps(
                get_audit_evidence(
                    finding["audit_event_id"],
                    finding["first_seen"],
                ),
                indent=2,
            ))

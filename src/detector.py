
import argparse
import sqlite3
import fcntl
import os
import time
from pathlib import Path
from datetime import datetime

from audit_parser import AUDIT_LOG, parse_audit_log
from correlator import correlate_events, get_username
from event_store import (
    save_finding, get_findings, resolve_finding_key,
    get_events_after, get_latest_event_id,
    get_detector_state, save_detector_state,
)


EVENT_RISK = {
    "CREATED": 5,
    "MODIFIED": 10,
    "DELETED": 30,
    "PERMISSION_CHANGED": 15,
    "ACCESS_DENIED": 25,
    "UNAUTHORIZED_MODIFICATION": 35,
}

WATCH_DIRECTORY = "/opt/organization/"


# ============================================================
# RISK SCORING
# ============================================================

def get_severity(score):
    """Convert a risk score into a provisional severity."""
    if score >= 40:
        return "CRITICAL"
    if score >= 25:
        return "HIGH"
    if score >= 10:
        return "MEDIUM"
    return "LOW"


def score_permission_change(mode):
    """
    Score a requested Unix permission mode.

    This evaluates the requested configuration, not whether
    permissions became more or less restrictive.

    Returns:
        (risk_score, explanation)
    """
    if mode is None:
        return (
            15,
            "Requested permission mode unavailable; impact unknown",
        )

    try:
        if isinstance(mode, str):
            value = int(mode, 8)
        elif isinstance(mode, int) and not isinstance(mode, bool):
            value = mode
        else:
            raise ValueError("Unsupported permission mode")

        if not 0 <= value <= 0o7777:
            raise ValueError("Permission mode outside valid range")

    except (ValueError, TypeError):
        return (
            15,
            "Requested permission mode malformed; impact unknown",
        )

    # Special permission bits can introduce privilege risks.
    if value & 0o6000:
        return (
            40,
            "Requested mode sets setuid/setgid bits; elevated risk",
        )

    # Write access for others.
    if value & 0o002:
        return (
            35,
            "Requested mode grants write access to others",
        )

    # Group write access.
    if value & 0o020:
        return (
            20,
            "Requested mode grants group write access",
        )

    # Read or execute access for others.
    if value & 0o007:
        return (
            10,
            "Requested mode grants read/execute access to others",
        )

    # Group read or execute access.
    if value & 0o070:
        return (
            10,
            "Requested mode grants group read/execute access",
        )

    return (
        5,
        "Requested mode limits access to the owner",
    )


# ============================================================
# AUDIT HELPERS
# ============================================================

def format_audit_timestamp(timestamp):
    """Convert an audit timestamp to the monitor timestamp format."""
    if timestamp is None:
        return None

    return datetime.fromtimestamp(timestamp).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def get_audit_file_path(event):
    """Select the relevant monitored path from an audit event."""
    paths = [
        path
        for path in event.get("paths", [])
        if path.startswith(WATCH_DIRECTORY)
    ]

    if not paths:
        return None

    non_parent_paths = [
        path
        for path in paths
        if not path.endswith("/")
    ]

    return (
        non_parent_paths[-1]
        if non_parent_paths
        else paths[-1]
    )


# ============================================================
# FILESYSTEM EVENT ASSESSMENT
# ============================================================

def assess_event(event):
    """Assess one correlated filesystem event."""
    event_type = event.get("event_type", "UNKNOWN")
    score = EVENT_RISK.get(event_type, 0)
    reasons = []

    new_mode = None

    if event_type == "PERMISSION_CHANGED":
        # Watchdog may report the observed new permissions.
        # Do not assume the previous mode if unavailable.
        details = event.get("details") or ""

        for field in details.split("|"):
            field = field.strip()

            if field.startswith("NEW="):
                new_mode = field[4:].strip()
                break

        score, explanation = score_permission_change(new_mode)

        reasons.append(
            f"PERMISSION_CHANGED: {explanation} (+{score})"
        )

    elif score:
        reasons.append(
            f"{event_type} event: +{score}"
        )

    matched = event.get("matched", False)

    if not matched:
        reasons.append(
            "Attribution warning: no matching audit record was found"
        )

    username = event.get("username")

    if username in (None, "", "unknown"):
        username = get_username(event.get("uid"))

    return {
        "timestamp": event.get("timestamp"),
        "sqlite_ids": (
            [event["sqlite_id"]]
            if event.get("sqlite_id") is not None
            else []
        ),
        "event_types": [event_type],
        "file_path": event.get("file_path"),
        "username": username,
        "matched": matched,
        "audit_event_id": event.get("audit_event_id"),
        "audit_timestamp": event.get("audit_timestamp"),
        "pid": event.get("pid"),
        "process": event.get("process", "unknown"),
        "permission_mode": new_mode,
        "risk_score": score,
        "severity": get_severity(score),
        "reasons": reasons,
    }


def merge_finding(existing, incoming):
    """
    Combine evidence associated with the same audit operation.

    Preserve event types and SQLite IDs while using the
    highest individual risk score.
    """
    for timestamp in incoming.get("event_timestamps", []):
        if (
            timestamp
            and timestamp not in existing["event_timestamps"]
        ):
            existing["event_timestamps"].append(timestamp)

    for sqlite_id in incoming.get("sqlite_ids", []):
        if sqlite_id not in existing["sqlite_ids"]:
            existing["sqlite_ids"].append(sqlite_id)

    for event_type in incoming.get("event_types", []):
        if event_type not in existing["event_types"]:
            existing["event_types"].append(event_type)

    for reason in incoming.get("reasons", []):
        if reason not in existing["reasons"]:
            existing["reasons"].append(reason)

    if incoming["risk_score"] > existing["risk_score"]:
        existing["risk_score"] = incoming["risk_score"]
        existing["severity"] = incoming["severity"]

    if incoming.get("permission_mode") is not None:
        existing["permission_mode"] = incoming["permission_mode"]

    if incoming.get("matched"):
        existing["matched"] = True

    if incoming.get("audit_timestamp") is not None:
        existing["audit_timestamp"] = incoming["audit_timestamp"]

    if incoming.get("username") not in (None, "", "unknown"):
        existing["username"] = incoming["username"]

    if incoming.get("pid") is not None:
        existing["pid"] = incoming["pid"]

    if incoming.get("process") not in (None, "", "unknown"):
        existing["process"] = incoming["process"]

    return existing


# ============================================================
# WATCHDOG / AUDIT CORRELATION DETECTION
# ============================================================

def detect_suspicious_activity(
    limit=100,
    sqlite_events=None,
    audit_events=None,
):
    """Group filesystem events associated with audit operations."""
    findings_by_key = {}

    for event in correlate_events(
        limit,
        sqlite_events=sqlite_events,
        audit_events=audit_events,
    ):
        finding = assess_event(event)

        finding["event_timestamps"] = (
            [finding["timestamp"]]
            if finding["timestamp"]
            else []
        )

        audit_id = finding["audit_event_id"]
        file_path = finding["file_path"]

        if finding["matched"] and audit_id is not None:
            key = (
                "audit",
                str(audit_id),
                finding.get("audit_timestamp"),
                file_path,
            )
        else:
            key = (
                "sqlite",
                str(event.get("sqlite_id")),
                file_path,
            )

        if key not in findings_by_key:
            findings_by_key[key] = finding
        else:
            merge_finding(
                findings_by_key[key],
                finding,
            )

    return list(findings_by_key.values())


# ============================================================
# DENIED ACCESS DETECTION
# ============================================================

def detect_denied_access(audit_events=None):
    """Find and classify denied filesystem operations."""
    findings = []
    seen = set()

    if audit_events is None:
        audit_events = parse_audit_log()

    for event in audit_events:
        if event.get("key") not in (
            "org_file_reads",
            "d3_denied_write",
        ):
            continue

        if event.get("success") != "no":
            continue

        if event.get("exit_code") != -13:
            continue

        file_path = get_audit_file_path(event)

        if file_path is None:
            continue

        audit_id = event.get("event_id")

        key = (
            str(audit_id),
            event.get("timestamp"),
            file_path,
        )

        if key in seen:
            continue

        seen.add(key)

        access_mode = event.get("access_mode")

        if access_mode in ("WRITE", "READ_WRITE"):
            event_type = "UNAUTHORIZED_MODIFICATION"
            reason = (
                "Unauthorized file modification attempt "
                "denied (EACCES)"
            )
        else:
            event_type = "ACCESS_DENIED"
            reason = (
                "Operating system denied access (EACCES)"
            )

        score = EVENT_RISK[event_type]

        event_timestamp = format_audit_timestamp(
            event.get("timestamp")
        )

        findings.append({
            "timestamp": event_timestamp,
            "event_timestamps": (
                [event_timestamp]
                if event_timestamp
                else []
            ),
            "sqlite_ids": [],
            "event_types": [event_type],
            "file_path": file_path,
            "username": get_username(event.get("euid")),
            "matched": True,
            "audit_event_id": audit_id,
            "audit_timestamp": event.get("timestamp"),
            "pid": event.get("pid"),
            "process": event.get("comm", "unknown"),
            "permission_mode": None,
            "risk_score": score,
            "severity": get_severity(score),
            "reasons": [reason],
        })

    return findings


# ============================================================
# PERMISSION CHANGE DETECTION
# ============================================================

def detect_permission_changes(audit_events=None):
    """
    Detect successful permission changes directly from auditd.

    Risk is determined by the requested permission mode instead
    of assigning a fixed HIGH severity to every chmod operation.

    The previous mode and authorization are not inferred.
    """
    findings = []
    seen = set()

    if audit_events is None:
        audit_events = parse_audit_log()

    for event in audit_events:
        if event.get("key") != "org_file_changes":
            continue

        if event.get("operation") != "PERMISSION_CHANGED":
            continue

        if event.get("success") != "yes":
            continue

        file_path = get_audit_file_path(event)

        if file_path is None:
            continue

        audit_id = event.get("event_id")

        if audit_id is None:
            continue

        key = (
            str(audit_id),
            event.get("timestamp"),
            file_path,
        )

        if key in seen:
            continue

        seen.add(key)

        permission_mode = event.get("permission_mode")

        score, explanation = score_permission_change(
            permission_mode
        )

        event_timestamp = format_audit_timestamp(
            event.get("timestamp")
        )

        reason = (
            "Successful permission-changing system call; "
            f"requested mode {permission_mode or 'unknown'}; "
            f"{explanation} (+{score}). "
            "Previous permissions and authorization not established."
        )

        findings.append({
            "timestamp": event_timestamp,
            "event_timestamps": (
                [event_timestamp]
                if event_timestamp
                else []
            ),
            "sqlite_ids": [],
            "event_types": ["PERMISSION_CHANGED"],
            "file_path": file_path,
            "username": get_username(event.get("euid")),
            "matched": True,
            "audit_event_id": audit_id,
            "audit_timestamp": event.get("timestamp"),
            "pid": event.get("pid"),
            "process": event.get("comm") or "unknown",
            "permission_mode": permission_mode,
            "risk_score": score,
            "severity": get_severity(score),
            "reasons": [reason],
        })

    return findings


# ============================================================
# FINDING MERGING AND PERSISTENCE
# ============================================================

def combine_findings(findings):
    """
    Merge findings referring to the same audit event and file.

    Findings without audit IDs remain separate.
    """
    combined = {}

    for finding in findings:
        audit_id = finding.get("audit_event_id")
        file_path = finding.get("file_path")

        if audit_id is not None:
            key = (
                "audit",
                str(audit_id),
                finding.get("audit_timestamp"),
                file_path,
            )
        else:
            sqlite_ids = finding.get("sqlite_ids", [])

            if not sqlite_ids:
                continue

            key = (
                "sqlite",
                str(sqlite_ids[0]),
                file_path,
            )

        if key not in combined:
            combined[key] = finding
        else:
            merge_finding(
                combined[key],
                finding,
            )

    return list(combined.values())


def persist_findings(findings):
    """Save findings using stable event identities."""
    saved = []

    for finding in findings:
        audit_id = finding.get("audit_event_id")
        sqlite_ids = finding.get("sqlite_ids", [])

        finding_key = resolve_finding_key(
            audit_id,
            finding.get("audit_timestamp"),
            finding["file_path"],
            sqlite_ids,
        )

        if finding_key is None:
            continue

        timestamps = finding.get("event_timestamps", [])

        if not timestamps:
            timestamps = [finding.get("timestamp")]

        timestamps = [
            value
            for value in timestamps
            if value
        ]

        if not timestamps:
            continue

        timestamp = max(timestamps)

        finding_id = save_finding(
            finding_key=finding_key,
            timestamp=timestamp,
            event_types=finding["event_types"],
            file_path=finding["file_path"],
            username=finding.get("username") or "unknown",
            audit_event_id=audit_id,
            risk_score=finding["risk_score"],
            severity=finding["severity"],
            reasons=finding["reasons"],
        )

        saved.append((finding_id, finding))

    return saved


def print_findings(saved_findings):
    """Display findings chronologically with database IDs."""
    saved_findings = sorted(
        saved_findings,
        key=lambda item: (
            min(item[1].get("event_timestamps", []))
            if item[1].get("event_timestamps")
            else item[1].get("timestamp") or ""
        ),
    )

    for finding_id, finding in saved_findings:
        print("-" * 60)
        print(f"Finding ID:   {finding_id}")

        timestamps = [
            ts
            for ts in finding.get("event_timestamps", [])
            if ts
        ]

        if timestamps:
            print(f"First seen:   {min(timestamps)}")
            print(f"Last seen:    {max(timestamps)}")

        elif finding.get("timestamp"):
            print(f"Timestamp:    {finding['timestamp']}")

        if finding["sqlite_ids"]:
            print(f"SQLite IDs:   {finding['sqlite_ids']}")

        print(
            f"Type:         {', '.join(finding['event_types'])}"
        )
        print(f"File:         {finding['file_path']}")
        print(f"User:         {finding['username']}")
        print(f"Audit match:  {finding['matched']}")
        print(f"Risk score:   {finding['risk_score']}")
        print(f"Severity:     {finding['severity']}")

        if finding.get("audit_event_id") is not None:
            print(f"Audit ID:     {finding['audit_event_id']}")

        if finding.get("pid") is not None:
            print(f"PID:          {finding['pid']}")

        print(f"Process:      {finding['process']}")

        if finding.get("permission_mode") is not None:
            print(
                "Requested permissions: "
                f"{finding['permission_mode']}"
            )

        print("Reasons:")

        for reason in finding["reasons"]:
            print(f"  - {reason}")


# ============================================================
# INCREMENTAL AUDIT PROCESSING
# ============================================================

AUDIT_OVERLAP_BYTES = 256 * 1024
BATCH_SIZE = 500


def audit_snapshot(state):
    """
    Read the recent audit-log region and capture its position.

    Changed inode or truncated file starts reading from the
    beginning of the new audit log.
    """
    stat_result = os.stat(AUDIT_LOG)

    identity = (
        f"{stat_result.st_dev}:{stat_result.st_ino}"
    )

    same_file = (
        state.get("audit_file_identity") == identity
    )

    old_offset = int(
        state.get("audit_offset", 0)
    )

    offset = (
        old_offset
        if same_file and old_offset <= stat_result.st_size
        else 0
    )

    start = max(
        0,
        offset - AUDIT_OVERLAP_BYTES,
    )

    events = parse_audit_log(
        start_offset=start
    )

    log_changed = (
        not same_file
        or stat_result.st_size != old_offset
    )

    return events, {
        "audit_file_identity": identity,
        "audit_offset": stat_result.st_size,
    }, log_changed


# ============================================================
# CONTINUOUS DETECTION
# ============================================================

def run_detection_cycle(state, verbose=False):
    """
    Process unseen Watchdog events and audit-only records.

    Checkpoints advance after successful processing.
    """
    audit_events, audit_position, log_changed = audit_snapshot(
        state
    )

    last_sqlite_id = int(
        state.get("last_sqlite_event_id", 0)
    )

    saved_count = 0
    processed_count = 0

    prior_audit_time = float(
        state.get("last_audit_timestamp", 0)
    )

    # Audit-only detection captures denied operations and
    # permission changes without requiring Watchdog events.
    audit_only_events = (
        [
            event
            for event in audit_events
            if event.get("timestamp") is not None
            and event["timestamp"] >= prior_audit_time - 1.0
        ]
        if log_changed
        else []
    )

    audit_findings = detect_denied_access(
        audit_only_events
    )

    audit_findings.extend(
        detect_permission_changes(audit_only_events)
    )

    audit_findings = combine_findings(
        audit_findings
    )

    saved_count += len(
        persist_findings(audit_findings)
    )

    # Process every unseen Watchdog event in bounded batches.
    while True:
        batch = get_events_after(
            last_sqlite_id,
            BATCH_SIZE,
        )

        if not batch:
            break

        findings = detect_suspicious_activity(
            sqlite_events=batch,
            audit_events=audit_events,
        )

        findings = combine_findings(
            findings
        )

        saved_count += len(
            persist_findings(findings)
        )

        last_sqlite_id = batch[-1][0]
        processed_count += len(batch)

    most_recent_audit = max(
        (
            event.get("timestamp", 0)
            for event in audit_events
        ),
        default=prior_audit_time,
    )

    new_state = {
        **audit_position,
        "last_sqlite_event_id": last_sqlite_id,
        "last_audit_timestamp": max(
            prior_audit_time,
            most_recent_audit,
        ),
    }

    save_detector_state(new_state)

    state.update({
        key: str(value)
        for key, value in new_state.items()
    })

    if verbose or saved_count or processed_count:
        print(
            f"Detection cycle: {processed_count} Watchdog events, "
            f"{len(audit_events)} audit records, "
            f"{saved_count} persisted/updated findings",
            flush=True,
        )

    return saved_count


def run_continuous(
    interval=5.0,
    verbose=False,
    start_now=False,
):
    """Continuously process incoming evidence."""
    if interval < 1:
        raise ValueError(
            "Polling interval must be at least 1 second"
        )

    state = get_detector_state()

    if "last_sqlite_event_id" not in state:
        if start_now:
            stat_result = os.stat(AUDIT_LOG)

            recent_events = parse_audit_log(
                start_offset=max(
                    0,
                    stat_result.st_size - AUDIT_OVERLAP_BYTES,
                )
            )

            state = {
                "last_sqlite_event_id": get_latest_event_id(),
                "audit_file_identity": (
                    f"{stat_result.st_dev}:{stat_result.st_ino}"
                ),
                "audit_offset": stat_result.st_size,
                "last_audit_timestamp": max(
                    (
                        event.get("timestamp", 0)
                        for event in recent_events
                    ),
                    default=0,
                ),
            }

            save_detector_state(state)

            print(
                "Checkpoint initialized at current log end; "
                "historical events intentionally skipped."
            )

        else:
            state = {
                "last_sqlite_event_id": "0",
                "audit_offset": "0",
                "audit_file_identity": "",
            }

            print(
                "No prior checkpoint: processing available history."
            )

    print(
        f"Continuous detector running (every {interval:g}s). "
        "Press Ctrl+C to stop.",
        flush=True,
    )

    while True:
        try:
            run_detection_cycle(
                state,
                verbose=verbose,
            )

        except (
            OSError,
            ValueError,
            RuntimeError,
            sqlite3.Error,
        ) as exc:
            print(
                f"Detection cycle failed ({type(exc).__name__}): "
                f"{exc}. Checkpoint not advanced; will retry.",
                flush=True,
            )

        time.sleep(interval)


# ============================================================
# COMMAND LINE INTERFACE
# ============================================================

def main():
    """Run detection once or continuously."""
    parser = argparse.ArgumentParser(
        description="File integrity detector"
    )

    mode = parser.add_mutually_exclusive_group()

    mode.add_argument(
        "--once",
        action="store_true",
        help="Run once (default)",
    )

    mode.add_argument(
        "--continuous",
        action="store_true",
        help="Poll continuously",
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
    )

    parser.add_argument(
        "--start-now",
        action="store_true",
        help=(
            "On first continuous start, "
            "skip existing historical evidence"
        ),
    )

    args = parser.parse_args()

    # Prevent multiple detector instances.
    os.makedirs("logs", exist_ok=True)

    with open("logs/detector.lock", "w") as lock:
        try:
            fcntl.flock(
                lock,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )

        except BlockingIOError:
            parser.error(
                "another detector process is already running"
            )

        if args.continuous:
            try:
                run_continuous(
                    args.interval,
                    verbose=args.verbose,
                    start_now=args.start_now,
                )

            except KeyboardInterrupt:
                print("Detector stopped.")

            return

        findings = detect_suspicious_activity()

        audit_events = parse_audit_log()

        findings.extend(
            detect_denied_access(audit_events)
        )

        findings.extend(
            detect_permission_changes(audit_events)
        )

        findings = combine_findings(findings)

        saved = persist_findings(findings)

        print_findings(saved)

        print(
            "\nPersisted finding count:",
            len(get_findings()),
        )


if __name__ == "__main__":
    main()

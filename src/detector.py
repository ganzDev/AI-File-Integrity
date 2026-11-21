
from datetime import datetime

from audit_parser import parse_audit_log
from correlator import correlate_events, get_username
from event_store import save_finding, get_findings


EVENT_RISK = {
    "CREATED": 5,
    "MODIFIED": 10,
    "DELETED": 30,
    "PERMISSION_CHANGED": 35,
    "ACCESS_DENIED": 25,
    "UNAUTHORIZED_MODIFICATION": 35,
}

WATCH_DIRECTORY = "/opt/organization/"


def get_severity(score):
    """Convert a risk score into a provisional severity."""
    if score >= 40:
        return "CRITICAL"
    if score >= 25:
        return "HIGH"
    if score >= 10:
        return "MEDIUM"
    return "LOW"


def format_audit_timestamp(timestamp):
    """Convert an audit timestamp to the monitor's timestamp format."""
    if timestamp is None:
        return None

    return datetime.fromtimestamp(timestamp).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def get_audit_file_path(event):
    """Select a file path from an audit record."""
    paths = [
        path
        for path in event.get("paths", [])
        if path.startswith(WATCH_DIRECTORY)
    ]

    if not paths:
        return None

    # Prefer the target over a directory recorded as its parent.
    non_parent_paths = [
        path for path in paths
        if not path.endswith("/")
    ]

    return (
        non_parent_paths[-1]
        if non_parent_paths
        else paths[-1]
    )


def assess_event(event):
    """Assess one filesystem event."""
    event_type = event.get("event_type", "UNKNOWN")
    score = EVENT_RISK.get(event_type, 0)
    reasons = []

    if score:
        reasons.append(f"{event_type} event: +{score}")

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
        "pid": event.get("pid"),
        "process": event.get("process", "unknown"),
        "permission_mode": None,
        "risk_score": score,
        "severity": get_severity(score),
        "reasons": reasons,
    }


def merge_finding(existing, incoming):
    """
    Combine evidence associated with the same audit event and file.

    Preserve distinct event types and SQLite IDs while using the
    highest individual event risk score.
    """
    for timestamp in incoming.get("event_timestamps", []):
        if timestamp and timestamp not in existing["event_timestamps"]:
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

    if incoming.get("username") not in (None, "", "unknown"):
        existing["username"] = incoming["username"]

    if incoming.get("pid") is not None:
        existing["pid"] = incoming["pid"]

    if incoming.get("process") not in (None, "", "unknown"):
        existing["process"] = incoming["process"]

    return existing


def detect_suspicious_activity(limit=100):
    """Group filesystem events associated with the same audit operation."""
    findings_by_key = {}

    for event in correlate_events(limit):
        finding = assess_event(event)
        finding["event_timestamps"] = (
            [finding["timestamp"]]
            if finding["timestamp"]
            else []
        )

        audit_id = finding["audit_event_id"]
        file_path = finding["file_path"]

        if finding["matched"] and audit_id is not None:
            key = ("audit", str(audit_id), file_path)
        else:
            key = (
                "sqlite",
                str(event.get("sqlite_id")),
                file_path,
            )

        if key not in findings_by_key:
            findings_by_key[key] = finding
        else:
            merge_finding(findings_by_key[key], finding)

    return list(findings_by_key.values())


def detect_denied_access(audit_events=None):
    """Find and classify permission-denied operations in audit logs."""
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
        key = (str(audit_id), file_path)

        if key in seen:
            continue

        seen.add(key)

        # Distinguish unauthorized writes from denied reads.
        access_mode = event.get("access_mode")

        if access_mode in ("WRITE", "READ_WRITE"):
            event_type = "UNAUTHORIZED_MODIFICATION"
            reason = (
                "Unauthorized file modification attempt "
                "denied (EACCES)"
            )
        else:
            event_type = "ACCESS_DENIED"
            reason = "Operating system denied access (EACCES)"

        score = EVENT_RISK[event_type]

        event_timestamp = format_audit_timestamp(
            event.get("timestamp")
        )

        findings.append({
            "timestamp": event_timestamp,
            "event_timestamps": (
                [event_timestamp] if event_timestamp else []
            ),
            "sqlite_ids": [],
            "event_types": [event_type],
            "file_path": file_path,
            "username": get_username(event.get("euid")),
            "matched": True,
            "audit_event_id": audit_id,
            "pid": event.get("pid"),
            "process": event.get("comm", "unknown"),
            "permission_mode": None,
            "risk_score": score,
            "severity": get_severity(score),
            "reasons": [reason],
        })

    return findings


def detect_permission_changes(audit_events=None):
    """
    Detect successful permission changes directly from auditd.

    This catches chmod-family operations even if Watchdog misses
    the change because it occurred too quickly.
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

        key = (str(audit_id), file_path)

        if key in seen:
            continue

        seen.add(key)

        permission_mode = event.get("permission_mode")
        score = EVENT_RISK["PERMISSION_CHANGED"]

        event_timestamp = format_audit_timestamp(
            event.get("timestamp")
        )

        if permission_mode is not None:
            reason = (
                "Successful permission-changing system call: "
                f"requested mode {permission_mode}"
            )
        else:
            reason = (
                "Successful permission-changing system call; "
                "requested mode unavailable"
            )

        findings.append({
            "timestamp": event_timestamp,
            "event_timestamps": (
                [event_timestamp] if event_timestamp else []
            ),
            "sqlite_ids": [],
            "event_types": ["PERMISSION_CHANGED"],
            "file_path": file_path,
            "username": get_username(event.get("euid")),
            "matched": True,
            "audit_event_id": audit_id,
            "pid": event.get("pid"),
            "process": event.get("comm") or "unknown",
            "permission_mode": permission_mode,
            "risk_score": score,
            "severity": get_severity(score),
            "reasons": [reason],
        })

    return findings


def combine_findings(findings):
    """
    Merge findings referring to the same audit event and file.

    Findings without an audit ID remain separate because their
    identity is based on their SQLite source event.
    """
    combined = {}

    for finding in findings:
        audit_id = finding.get("audit_event_id")
        file_path = finding.get("file_path")

        if audit_id is not None:
            key = ("audit", str(audit_id), file_path)
        else:
            sqlite_ids = finding.get("sqlite_ids", [])

            if not sqlite_ids:
                continue

            key = ("sqlite", str(sqlite_ids[0]), file_path)

        if key not in combined:
            combined[key] = finding
        else:
            merge_finding(combined[key], finding)

    return list(combined.values())


def persist_findings(findings):
    """Save findings using stable keys and return their database IDs."""
    saved = []

    for finding in findings:
        audit_id = finding.get("audit_event_id")
        sqlite_ids = finding.get("sqlite_ids", [])

        if audit_id is not None:
            finding_key = (
                f"audit:{audit_id}:{finding['file_path']}"
            )
        elif sqlite_ids:
            finding_key = (
                f"sqlite:{sqlite_ids[0]}:{finding['file_path']}"
            )
        else:
            # Do not persist findings without a stable source identifier.
            continue

        timestamps = finding.get("event_timestamps", [])

        if not timestamps:
            timestamps = [finding.get("timestamp")]

        timestamps = [
            value for value in timestamps if value
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
    """Print findings chronologically using permanent database IDs."""
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
            ts for ts in finding.get("event_timestamps", [])
            if ts
        ]

        if timestamps:
            print(f"First seen:   {min(timestamps)}")
            print(f"Last seen:    {max(timestamps)}")
        elif finding.get("timestamp"):
            print(f"Timestamp:    {finding['timestamp']}")

        if finding["sqlite_ids"]:
            print(f"SQLite IDs:   {finding['sqlite_ids']}")

        print(f"Type:         {', '.join(finding['event_types'])}")
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
                f"Requested permissions: "
                f"{finding['permission_mode']}"
            )

        print("Reasons:")

        for reason in finding["reasons"]:
            print(f"  - {reason}")


def main():
    """Run all detection sources and persist findings."""
    findings = detect_suspicious_activity()

    # Parse the audit log once for both audit-based detectors.
    audit_events = parse_audit_log()

    findings.extend(detect_denied_access(audit_events))
    findings.extend(detect_permission_changes(audit_events))

    # Merge findings that refer to the exact same audit operation.
    findings = combine_findings(findings)

    saved = persist_findings(findings)
    print_findings(saved)

    print("\nPersisted finding count:", len(get_findings()))


if __name__ == "__main__":
    main()

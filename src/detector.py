
from datetime import datetime, timezone

from audit_parser import parse_audit_log
from correlator import correlate_events, get_username
from event_store import save_finding, get_findings


EVENT_RISK = {
    "CREATED": 5,
    "MODIFIED": 10,
    "DELETED": 30,
    "PERMISSION_CHANGED": 35,
    "ACCESS_DENIED": 25,
}


def get_severity(score):
    """Convert a risk score into a provisional severity."""
    if score >= 40:
        return "CRITICAL"
    if score >= 25:
        return "HIGH"
    if score >= 10:
        return "MEDIUM"
    return "LOW"


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
        "risk_score": score,
        "severity": get_severity(score),
        "reasons": reasons,
    }


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
            continue

        existing = findings_by_key[key]
        existing["event_timestamps"].extend(
            finding["event_timestamps"]
        )
        existing["sqlite_ids"].extend(finding["sqlite_ids"])

        for event_type in finding["event_types"]:
            if event_type not in existing["event_types"]:
                existing["event_types"].append(event_type)

        if finding["risk_score"] > existing["risk_score"]:
            existing["risk_score"] = finding["risk_score"]
            existing["severity"] = finding["severity"]

        for reason in finding["reasons"]:
            if reason not in existing["reasons"]:
                existing["reasons"].append(reason)

    return list(findings_by_key.values())


def detect_denied_access():
    """Find permission-denied operations in audit logs."""
    findings = []
    seen = set()

    for event in parse_audit_log():
        if event.get("key") != "org_file_reads":
            continue
        if event.get("success") != "no":
            continue
        if event.get("exit_code") != -13:
            continue

        paths = [
            path for path in event.get("paths", [])
            if path.startswith("/opt/organization/")
        ]
        if not paths:
            continue

        file_path = paths[-1]
        audit_id = event.get("event_id")
        key = (str(audit_id), file_path)

        if key in seen:
            continue
        seen.add(key)

        score = EVENT_RISK["ACCESS_DENIED"]

        event_timestamp = event.get("timestamp")
        if event_timestamp is not None:
            event_timestamp = datetime.fromtimestamp(
                event_timestamp
            ).strftime("%Y-%m-%d %H:%M:%S")

        findings.append({
            "timestamp": event_timestamp,
            "event_timestamps": (
                [event_timestamp] if event_timestamp else []
            ),
            "sqlite_ids": [],
            "event_types": ["ACCESS_DENIED"],
            "file_path": file_path,
            "username": get_username(event.get("euid")),
            "matched": True,
            "audit_event_id": audit_id,
            "pid": event.get("pid"),
            "process": event.get("comm", "unknown"),
            "risk_score": score,
            "severity": get_severity(score),
            "reasons": [
                "Operating system denied access (EACCES)"
            ],
        })

    return findings


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
            # Do not persist a finding without a stable source identifier.
            continue


        timestamps = finding.get("event_timestamps", [])

        if not timestamps:
            timestamps = [finding.get("timestamp")]

        timestamps = [value for value in timestamps if value]

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
    """Print persisted findings using their permanent database IDs."""
    for finding_id, finding in saved_findings:
        print("-" * 60)
        print(f"Finding ID:   {finding_id}")

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
        print("Reasons:")
        for reason in finding["reasons"]:
            print(f"  - {reason}")


if __name__ == "__main__":
    findings = detect_suspicious_activity()
    findings.extend(detect_denied_access())

    saved = persist_findings(findings)
    print_findings(saved)

    print("\nPersisted finding count:", len(get_findings()))

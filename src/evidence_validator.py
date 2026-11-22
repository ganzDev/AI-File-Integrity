
"""Evidence validation for AI-generated security assessments.

Supports:
1. Structured audit claims produced by the AI investigator.
2. Reference checking for previously saved assessments.

Validation is read-only. It does not establish authorization,
intent, or the correctness of an overall threat classification.
"""

import argparse
import json
import re
import sqlite3
from datetime import datetime

from audit_parser import parse_audit_log
from correlator import get_username
from event_store import DATABASE_PATH


MAX_CLAIMS = 20
MAX_REFERENCE_SECONDS = 10
TIMESTAMP_TOLERANCE = 1.0

AUDIT_REFERENCE_PATTERN = re.compile(
    r"\baudit\s+events?\s+"
    r"(\d+(?:\s*(?:,|and)\s*\d+)*)",
    re.IGNORECASE,
)

NEGATIVE_CLAIM_PATTERN = re.compile(
    r"\b("
    r"no other suspicious activity|"
    r"no other related activity|"
    r"no prior (?:file )?(?:modification|activity|history)|"
    r"no related authorized (?:activity|events)|"
    r"no evidence of (?:other|additional|prior)|"
    r"absence of (?:other|related|prior)|"
    r"isolated (?:incident|event|attempt)|"
    r"no (?:file )?history"
    r")\b",
    re.IGNORECASE,
)


def get_reference_time(finding):
    """Convert the stored finding timestamp into Unix time."""
    return datetime.strptime(
        finding["first_seen"][:19],
        "%Y-%m-%d %H:%M:%S",
    ).timestamp()


def find_audit_record(
    audit_events,
    event_id,
    reference_time,
    claimed_timestamp=None,
):
    """Locate exactly one audit record matching the event and time."""
    matches = []

    for event in audit_events:
        if str(event.get("event_id")) != str(event_id):
            continue

        if event.get("syscall") is None:
            continue

        timestamp = event.get("timestamp")

        if timestamp is None:
            continue

        if abs(timestamp - reference_time) > MAX_REFERENCE_SECONDS:
            continue

        if (
            claimed_timestamp is not None
            and abs(timestamp - claimed_timestamp)
            > TIMESTAMP_TOLERANCE
        ):
            continue

        matches.append(event)

    return matches[0] if len(matches) == 1 else None


def check_audit_properties(event, expected):
    """Compare claimed syscall properties with actual audit fields."""
    fields = {
        "syscall": "syscall",
        "access_mode": "access_mode",
        "success": "success",
        "exit_code": "exit_code",
        "pid": "pid",
        "process": "comm",
        "permission_mode": "permission_mode",
    }

    checks = {}

    for claim_field, audit_field in fields.items():
        if claim_field not in expected:
            continue

        actual = event.get(audit_field)
        claimed = expected[claim_field]

        checks[claim_field] = {
            "expected": claimed,
            "actual": actual,
            "matches": actual == claimed,
        }

    if "file_path" in expected:
        path = expected["file_path"]
        paths = event.get("paths") or []

        checks["file_path"] = {
            "expected": path,
            "actual": paths,
            "matches": path in paths,
        }

    return {
        "checks": checks,
        "all_checks_passed": (
            bool(checks)
            and all(
                item["matches"]
                for item in checks.values()
            )
        ),
    }


def validate_assessment_claims(finding, assessment):
    """Validate structured audit claims from an AI assessment."""
    claims = assessment.get("audit_claims", [])

    if not isinstance(claims, list):
        return {
            "status": "NEEDS_REVIEW",
            "verified": 0,
            "total": 0,
            "results": [],
            "warnings": ["audit_claims must be a list"],
        }

    if not claims:
        return {
            "status": "NEEDS_REVIEW",
            "verified": 0,
            "total": 0,
            "results": [],
            "warnings": [
                "No structured audit claims were provided."
            ],
        }

    reference_time = get_reference_time(finding)
    target_path = finding["file_path"]
    target_directory = target_path.rsplit("/", 1)[0]

    audit_events = parse_audit_log()

    results = []
    warnings = []
    verified = 0

    if len(claims) > MAX_CLAIMS:
        warnings.append(
            f"Only the first {MAX_CLAIMS} claims can be checked."
        )

    for index, claim in enumerate(claims[:MAX_CLAIMS], start=1):
        result = {
            "claim_number": index,
            "audit_event_id": (
                str(claim.get("audit_event_id", ""))
                if isinstance(claim, dict) else ""
            ),
            "status": "REVIEW",
            "issues": [],
        }

        if not isinstance(claim, dict):
            result["issues"].append(
                "Claim must be a JSON object."
            )
            results.append(result)
            continue

        try:
            event_id = str(claim["audit_event_id"])
            claimed_timestamp = float(claim["timestamp"])

            event = find_audit_record(
                audit_events,
                event_id,
                reference_time,
                claimed_timestamp,
            )

            if event is None:
                result["issues"].append(
                    "No unique audit record matches "
                    "the event ID and timestamps."
                )
                results.append(result)
                continue

            expected = {
                field: claim[field]
                for field in (
                    "syscall",
                    "access_mode",
                    "success",
                    "exit_code",
                    "process",
                    "file_path",
                )
            }

            comparison = check_audit_properties(
                event,
                expected,
            )

            result["checks"] = comparison["checks"]

            if not comparison["all_checks_passed"]:
                result["issues"].append(
                    "One or more syscall properties differ "
                    "from the audit record."
                )

            euid = event.get("euid")

            if euid is None:
                result["issues"].append(
                    "Audit record has no effective UID."
                )
            elif get_username(euid) != finding["username"]:
                result["issues"].append(
                    "Audit user differs from finding user."
                )

            paths = event.get("paths") or []

            if not any(
                path == target_path
                or path.startswith(target_directory + "/")
                for path in paths
            ):
                result["issues"].append(
                    "Event is outside the finding's "
                    "file/directory scope."
                )

            if not result["issues"]:
                result["status"] = "VERIFIED_FIELDS"
                verified += 1

        except (KeyError, ValueError, TypeError, OverflowError) as exc:
            result["issues"].append(
                f"Invalid claim: {type(exc).__name__}: {exc}"
            )

        results.append(result)

    status = (
        "VERIFIED_FIELDS"
        if verified == len(claims) and not warnings
        else "NEEDS_REVIEW"
    )

    return {
        "status": status,
        "verified": verified,
        "total": len(claims),
        "results": results,
        "warnings": warnings,
        "scope": (
            "Only structured audit properties were checked. "
            "Authorization, intent, uncited statements, "
            "and final classification remain unverified."
        ),
    }


def assessment_statements(assessment):
    """Collect relevant natural-language assessment statements."""
    fields = (
        "summary",
        "observed_facts",
        "inferences",
        "evidence",
        "analysis",
        "confidence_reason",
        "limitations",
    )

    statements = []

    for field in fields:
        value = assessment.get(field)

        if isinstance(value, str):
            statements.append((field, value))

        elif isinstance(value, list):
            statements.extend(
                (field, item)
                for item in value
                if isinstance(item, str)
            )

    return statements


def extract_audit_references(statements):
    """Find explicit audit event citations in free-form text."""
    references = {}

    for field, statement in statements:
        for match in AUDIT_REFERENCE_PATTERN.finditer(statement):
            event_ids = re.findall(r"\d+", match.group(1))

            for event_id in event_ids:
                references.setdefault(event_id, []).append({
                    "field": field,
                    "statement": statement,
                })

    return references


def validate_saved_assessment(assessment_id):
    """Validate references in an existing assessment without editing it."""
    database = DATABASE_PATH.resolve()

    with sqlite3.connect(
        database.as_uri() + "?mode=ro",
        uri=True,
    ) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT
                a.id AS assessment_id,
                a.finding_id,
                a.assessment_json,
                f.first_seen,
                f.file_path,
                f.username,
                f.audit_event_id
            FROM ai_assessments AS a
            JOIN findings AS f
                ON f.id = a.finding_id
            WHERE a.id = ?
            """,
            (assessment_id,),
        ).fetchone()

    if row is None:
        raise ValueError(
            f"Assessment {assessment_id} was not found."
        )

    finding = dict(row)
    assessment = json.loads(finding["assessment_json"])

    statements = assessment_statements(assessment)
    references = extract_audit_references(statements)

    # Include machine-readable references for newer reports.
    for claim in assessment.get("audit_claims", []):
        if isinstance(claim, dict):
            event_id = str(claim.get("audit_event_id", ""))
            if event_id:
                references.setdefault(event_id, [])

    reference_time = get_reference_time(finding)
    audit_events = parse_audit_log()

    results = []
    warnings = []

    primary_id = str(finding.get("audit_event_id") or "")

    if not references:
        warnings.append(
            "No explicit audit references were found."
        )
    elif primary_id and primary_id not in references:
        warnings.append(
            f"Primary audit event {primary_id} was not cited."
        )

    for event_id in references:
        event = find_audit_record(
            audit_events,
            event_id,
            reference_time,
        )

        if event is None:
            results.append({
                "audit_event_id": event_id,
                "status": "REVIEW",
                "issues": [
                    "No unique matching audit record "
                    "was found within the time window."
                ],
            })
            continue

        issues = []
        paths = event.get("paths") or []
        target_path = finding["file_path"]
        target_directory = target_path.rsplit("/", 1)[0]

        if not any(
            path == target_path
            or path.startswith(target_directory + "/")
            for path in paths
        ):
            issues.append(
                "Event does not match the finding's "
                "file/directory scope."
            )

        euid = event.get("euid")

        if euid is None:
            issues.append("Effective UID unavailable.")
        elif get_username(euid) != finding["username"]:
            issues.append("Audit user differs from finding user.")

        results.append({
            "audit_event_id": event_id,
            "status": (
                "REVIEW" if issues else "VERIFIED_REFERENCE"
            ),
            "operation": event.get("operation"),
            "access_mode": event.get("access_mode"),
            "success": event.get("success"),
            "exit_code": event.get("exit_code"),
            "pid": event.get("pid"),
            "process": event.get("comm"),
            "paths": paths,
            "issues": issues,
        })

    for field, statement in statements:
        if NEGATIVE_CLAIM_PATTERN.search(statement):
            warnings.append(
                f"Potentially unsupported negative claim "
                f"in {field}: {statement}"
            )

    verified_count = sum(
        result["status"] == "VERIFIED_REFERENCE"
        for result in results
    )

    return {
        "assessment_id": assessment_id,
        "finding_id": finding["finding_id"],
        "referenced_audit_ids": len(references),
        "verified_references": verified_count,
        "references": results,
        "warnings": warnings,
        "note": (
            "Reference verification confirms event association, "
            "not the accuracy of every AI statement."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Validate saved AI investigation evidence"
    )

    parser.add_argument(
        "--assessment",
        type=int,
        required=True,
        help="Saved AI assessment ID",
    )

    args = parser.parse_args()

    try:
        result = validate_saved_assessment(
            args.assessment
        )
        print(json.dumps(result, indent=2))

    except (
        ValueError,
        TypeError,
        OSError,
        sqlite3.Error,
        json.JSONDecodeError,
    ) as exc:
        parser.exit(1, f"Validation error: {exc}\n")



def check_incident_coverage(finding, assessment, validation):
    """
    Measure the proportion of correlated incident events
    represented by independently verified audit claims.

    Coverage is separate from claim validity and does not
    establish malicious intent or authorization.
    """
    from investigation_tools import get_incident_context

    def make_result(
        status,
        covered=0,
        total=0,
        missing=None,
        reason=None,
    ):
        return {
            "status": status,
            "covered": covered,
            "total": total,
            "percentage": (
                round(covered / total * 100, 1)
                if total > 0 else None
            ),
            "missing_event_ids": missing or [],
            "reason": reason,
        }

    audit_event_id = finding.get("audit_event_id")
    timestamp = finding.get("first_seen")

    if not audit_event_id or timestamp is None:
        return make_result(
            "UNAVAILABLE",
            reason="Finding lacks audit identification data.",
        )

    try:
        incident = get_incident_context(
            audit_event_id=str(audit_event_id),
            timestamp=timestamp,
            window_seconds=5,
        )

    except Exception as exc:
        return make_result(
            "UNAVAILABLE",
            reason=f"Incident retrieval failed: {type(exc).__name__}",
        )

    if incident.get("status") != "GROUP_DETECTED":
        return make_result(
            "NOT_APPLICABLE",
            reason="No correlated multi-event incident detected.",
        )

    events = incident.get("events", [])

    def event_key(event):
        """
        Match audit ID, second-level timestamp, and file path.

        Second-level comparison tolerates AI claims that omit
        fractional seconds.
        """
        try:
            return (
                str(event["audit_event_id"]),
                int(float(event["timestamp"])),
                str(event["file_path"]),
            )
        except (KeyError, TypeError, ValueError):
            return None

    expected = {
        key
        for event in events
        if (key := event_key(event)) is not None
    }

    if not expected or len(expected) != len(events):
        return make_result(
            "UNAVAILABLE",
            reason=(
                "Incident event identities are incomplete "
                "or ambiguous."
            ),
        )

    claims = assessment.get("audit_claims", [])
    results = validation.get("results", [])

    verified_keys = set()

    for result in results:
        if result.get("status") != "VERIFIED_FIELDS":
            continue

        claim_number = result.get("claim_number")

        if not isinstance(claim_number, int):
            continue

        index = claim_number - 1

        if not 0 <= index < len(claims):
            continue

        claim = claims[index]
        key = event_key(claim)

        if key is None:
            continue

        if str(result.get("audit_event_id")) != key[0]:
            continue

        verified_keys.add(key)

    covered_keys = expected & verified_keys
    missing_keys = expected - covered_keys

    covered = len(covered_keys)
    total = len(expected)

    return make_result(
        status=(
            "COMPLETE"
            if covered == total
            else "INCOMPLETE"
        ),
        covered=covered,
        total=total,
        missing=[
            event_id
            for event_id, _, _ in sorted(missing_keys)
        ],
    )


if __name__ == "__main__":
    main()

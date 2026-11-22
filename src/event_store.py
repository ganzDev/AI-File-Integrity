import sqlite3
from pathlib import Path


DATABASE_PATH = Path("logs/security_events.db")


def initialize_database():
    """Create the database tables if they do not exist."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                details TEXT
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS detector_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_key TEXT NOT NULL UNIQUE,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                event_types TEXT NOT NULL,
                file_path TEXT NOT NULL,
                username TEXT NOT NULL,
                audit_event_id TEXT,
                risk_score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                reasons TEXT NOT NULL
            )
        """)


def insert_event(timestamp, event_type, file_path, details=""):
    """Store one filesystem event in the database."""
    initialize_database()

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("""
            INSERT INTO events (
                timestamp, event_type, file_path, details
            )
            VALUES (?, ?, ?, ?)
        """, (timestamp, event_type, file_path, details))


def get_recent_events(limit=10):
    """Return the most recent filesystem events."""
    initialize_database()

    with sqlite3.connect(DATABASE_PATH) as connection:
        return connection.execute("""
            SELECT id, timestamp, event_type, file_path, details
            FROM events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()


def save_finding(
    finding_key,
    timestamp,
    event_types,
    file_path,
    username,
    audit_event_id,
    risk_score,
    severity,
    reasons,
):
    """Insert a finding or update an existing finding with the same key."""
    initialize_database()

    event_types_text = ", ".join(event_types)
    reasons_text = "\n".join(reasons)

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("""
            INSERT INTO findings (
                finding_key, first_seen, last_seen, event_types,
                file_path, username, audit_event_id,
                risk_score, severity, reasons
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_key) DO UPDATE SET
                first_seen = MIN(findings.first_seen, excluded.first_seen),
                last_seen = MAX(findings.last_seen, excluded.last_seen),
                event_types = excluded.event_types,
                username = excluded.username,
                audit_event_id = excluded.audit_event_id,
                risk_score = excluded.risk_score,
                severity = excluded.severity,
                reasons = excluded.reasons
        """, (
            finding_key,
            timestamp,
            timestamp,
            event_types_text,
            file_path,
            username,
            str(audit_event_id) if audit_event_id is not None else None,
            risk_score,
            severity,
            reasons_text,
        ))

        row = connection.execute(
            "SELECT id FROM findings WHERE finding_key = ?",
            (finding_key,),
        ).fetchone()

        return row[0]


def get_findings(limit=100):
    """Return persisted findings, newest IDs first."""
    initialize_database()

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("""
            SELECT *
            FROM findings
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]


def get_events_after(last_id, limit=500):
    """Fetch a bounded, ascending batch; no event can be skipped by LIMIT."""
    initialize_database()
    with sqlite3.connect(DATABASE_PATH) as connection:
        return connection.execute("""
            SELECT id, timestamp, event_type, file_path, details
            FROM events WHERE id > ? ORDER BY id ASC LIMIT ?
        """, (last_id, limit)).fetchall()


def get_latest_event_id():
    initialize_database()
    with sqlite3.connect(DATABASE_PATH) as connection:
        return connection.execute(
            "SELECT COALESCE(MAX(id), 0) FROM events"
        ).fetchone()[0]


def get_detector_state():
    initialize_database()
    with sqlite3.connect(DATABASE_PATH) as connection:
        return dict(connection.execute(
            "SELECT key, value FROM detector_state"
        ).fetchall())


def save_detector_state(values):
    """Checkpoint only after all findings for the cycle are saved."""
    initialize_database()
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.executemany("""
            INSERT INTO detector_state (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """, [(key, str(value)) for key, value in values.items()])


def resolve_finding_key(audit_id, audit_timestamp, file_path, sqlite_ids):
    """Use precise audit identity while reusing matching legacy records.

    An existing legacy finding is reused only if its first_seen falls
    within the original audit/Watchdog correlation tolerance.
    """
    if audit_id is None:
        return (f"sqlite:{sqlite_ids[0]}:{file_path}"
                if sqlite_ids else None)

    if audit_timestamp is None:
        # No true audit identity: do not invent a timestamp from Watchdog.
        return (f"sqlite:{sqlite_ids[0]}:{file_path}"
                if sqlite_ids else None)

    from datetime import datetime

    legacy_key = f"audit:{audit_id}:{file_path}"
    with sqlite3.connect(DATABASE_PATH) as connection:
        row = connection.execute(
            "SELECT first_seen FROM findings WHERE finding_key = ?",
            (legacy_key,),
        ).fetchone()

    if row:
        try:
            original_time = datetime.strptime(
                row[0][:19], "%Y-%m-%d %H:%M:%S"
            ).timestamp()
            if abs(original_time - float(audit_timestamp)) <= 5.0:
                return legacy_key
        except (ValueError, TypeError, OverflowError):
            pass

    return f"audit2:{audit_id}:{float(audit_timestamp):.6f}:{file_path}"

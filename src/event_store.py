
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

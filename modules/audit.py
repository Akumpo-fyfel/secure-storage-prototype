import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "service" / "audit.db"


def log_event(username, event_type, result, object_type=None, object_name=None, details=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO audit_events (
            event_time,
            username,
            event_type,
            object_type,
            object_name,
            result,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        username,
        event_type,
        object_type,
        object_name,
        result,
        details
    ))

    conn.commit()
    conn.close()


def list_events():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            event_time,
            username,
            event_type,
            object_type,
            object_name,
            result,
            details
        FROM audit_events
        ORDER BY id DESC
    """)

    events = cursor.fetchall()
    conn.close()

    return events

def clear_events():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM audit_events")

    conn.commit()
    conn.close()


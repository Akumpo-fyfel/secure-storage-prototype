import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "service" / "audit.db"

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT NOT NULL,
    username TEXT,
    event_type TEXT NOT NULL,
    object_type TEXT,
    object_name TEXT,
    result TEXT NOT NULL,
    details TEXT
)
""")

conn.commit()
conn.close()

print("audit.db initialized")
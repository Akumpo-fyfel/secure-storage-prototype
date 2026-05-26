import sqlite3

DB_PATH = "storage/encrypted_metadata/files.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stored_name TEXT UNIQUE NOT NULL,
    original_name TEXT NOT NULL,
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    status TEXT NOT NULL
)
""")

conn.commit()
conn.close()

print("files.db initialized")

import sqlite3

DB_PATH = "service/access.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS access_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL
)
""")

cursor.execute("""
INSERT OR IGNORE INTO access_rules (username, role)
VALUES (?, ?)
""", ("admin", "administrator"))

conn.commit()
conn.close()

print("access.db initialized")

import sqlite3
import os
import hashlib
import binascii
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "service" / "login.db"


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )


DB_PATH.parent.mkdir(parents=True, exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    failed_attempts INTEGER DEFAULT 0,
    failed_window_start TEXT
)
""")

# Миграция старой БД, если таблица users уже была создана без новых колонок
cursor.execute("PRAGMA table_info(users)")
columns = [row[1] for row in cursor.fetchall()]

if "status" not in columns:
    cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")

if "failed_attempts" not in columns:
    cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")

if "failed_window_start" not in columns:
    cursor.execute("ALTER TABLE users ADD COLUMN failed_window_start TEXT")

username = "admin"
password = "admin"

salt = os.urandom(16)
password_hash = hash_password(password, salt)

cursor.execute("""
INSERT OR IGNORE INTO users (
    username,
    password_hash,
    salt,
    status,
    failed_attempts,
    failed_window_start
)
VALUES (?, ?, ?, ?, ?, ?)
""", (
    username,
    binascii.hexlify(password_hash).decode("utf-8"),
    binascii.hexlify(salt).decode("utf-8"),
    "active",
    0,
    None
))

conn.commit()
conn.close()

print("login.db initialized")
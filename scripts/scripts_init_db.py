import sqlite3
import os
import hashlib
import binascii


DB_PATH = "service/login.db"


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL
)
""")

username = "admin"
password = "admin"

salt = os.urandom(16)
password_hash = hash_password(password, salt)

cursor.execute("""
INSERT OR IGNORE INTO users (
    username,
    password_hash,
    salt
)
VALUES (?, ?, ?)
""", (
    username,
    binascii.hexlify(password_hash).decode("utf-8"),
    binascii.hexlify(salt).decode("utf-8")
))

conn.commit()
conn.close()

print("login.db initialized")

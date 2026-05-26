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


def create_user(username, password, status="active"):
    salt = os.urandom(16)
    password_hash = hash_password(password, salt)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                salt,
                status,
                failed_attempts,
                failed_window_start
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                binascii.hexlify(password_hash).decode("utf-8"),
                binascii.hexlify(salt).decode("utf-8"),
                status,
                0,
                None
            )
        )

        conn.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    finally:
        conn.close()


def list_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, username, status, failed_attempts, failed_window_start
        FROM users
        ORDER BY id
        """
    )

    users = cursor.fetchall()
    conn.close()

    return users


def delete_user(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM users WHERE username=?",
        (username,)
    )

    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    return deleted > 0

def change_password(username, new_password):
    salt = os.urandom(16)
    password_hash = hash_password(new_password, salt)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET password_hash=?, salt=?
        WHERE username=?
        """,
        (
            binascii.hexlify(password_hash).decode("utf-8"),
            binascii.hexlify(salt).decode("utf-8"),
            username
        )
    )

    changed = cursor.rowcount
    conn.commit()
    conn.close()

    return changed > 0


def get_user_status(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT status FROM users WHERE username=?",
        (username,)
    )

    row = cursor.fetchone()
    conn.close()

    return row[0] if row else None


def set_user_status(username, status):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET status=? WHERE username=?",
        (status, username)
    )

    conn.commit()
    conn.close()


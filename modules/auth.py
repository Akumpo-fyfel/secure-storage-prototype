import sqlite3
import hashlib
import binascii
import hmac


DB_PATH = "service/login.db"

from modules.bruteforce import is_login_denied_by_status, register_failed_login, reset_failed_logins


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )


def verify_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT password_hash, salt, status
        FROM users
        WHERE username=?
        """,
        (username,)
    )

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    stored_hash_hex, salt_hex, status = row

    # blocked — заблокирован из-за перебора
    # used — одноразовая учётная запись уже использована
    if is_login_denied_by_status(status):
        return None

    salt = binascii.unhexlify(salt_hex)
    stored_hash = binascii.unhexlify(stored_hash_hex)

    calculated_hash = hash_password(password, salt)

    if hmac.compare_digest(calculated_hash, stored_hash):
        reset_failed_logins(username)

        return {
            "username": username
        }

    register_failed_login(username)

    return None

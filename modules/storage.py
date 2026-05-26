# modules/storage.py

import sqlite3
from pathlib import Path
from datetime import datetime
from werkzeug.utils import secure_filename

from modules.crypto import encrypt_file_data, decrypt_file_data


BASE_DIR = Path(__file__).resolve().parent.parent

STORAGE_DIR = BASE_DIR / "storage" / "encrypted_files"
KEYS_DIR = BASE_DIR / "storage" / "encrypted_file_keys"
DB_PATH = BASE_DIR / "storage" / "encrypted_metadata" / "files.db"


def _get_encrypted_file_path(stored_name):
    stored_name = secure_filename(stored_name)
    return STORAGE_DIR / stored_name


def _get_encrypted_key_path(stored_name):
    stored_name = secure_filename(stored_name)
    return KEYS_DIR / f"{stored_name}.key"


def save_file(file, uploaded_by, progress_callback=None):
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    original_name = file.filename
    stored_name = secure_filename(original_name)

    if not stored_name:
        return None

    plain_data = file.read()

    encrypted_data, wrapped_file_key = encrypt_file_data(
        plain_data,
        progress_callback=progress_callback
    )

    encrypted_file_path = _get_encrypted_file_path(stored_name)
    encrypted_key_path = _get_encrypted_key_path(stored_name)

    encrypted_file_path.write_bytes(encrypted_data)
    encrypted_key_path.write_bytes(wrapped_file_key)

    size_bytes = len(plain_data)
    uploaded_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO files (
            stored_name,
            original_name,
            uploaded_by,
            uploaded_at,
            size_bytes,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            stored_name,
            original_name,
            uploaded_by,
            uploaded_at,
            size_bytes,
            "active"
        )
    )

    conn.commit()
    conn.close()

    return stored_name


def list_files():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            stored_name,
            original_name,
            uploaded_by,
            uploaded_at,
            size_bytes,
            status
        FROM files
        WHERE status='active'
        ORDER BY uploaded_at DESC
    """)

    files = cursor.fetchall()
    conn.close()

    return files


def get_decrypted_file_data(filename):
    stored_name = secure_filename(filename)

    encrypted_file_path = _get_encrypted_file_path(stored_name)
    encrypted_key_path = _get_encrypted_key_path(stored_name)

    if not encrypted_file_path.exists():
        raise FileNotFoundError("Зашифрованный файл не найден")

    if not encrypted_key_path.exists():
        raise FileNotFoundError("Зашифрованный файловый ключ не найден")

    encrypted_data = encrypted_file_path.read_bytes()
    wrapped_file_key = encrypted_key_path.read_bytes()

    return decrypt_file_data(encrypted_data, wrapped_file_key)


def get_original_filename(stored_name):
    stored_name = secure_filename(stored_name)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT original_name
        FROM files
        WHERE stored_name=? AND status='active'
        """,
        (stored_name,)
    )

    row = cursor.fetchone()
    conn.close()

    if row:
        return row[0]

    return stored_name


def delete_file(filename):
    stored_name = secure_filename(filename)

    encrypted_file_path = _get_encrypted_file_path(stored_name)
    encrypted_key_path = _get_encrypted_key_path(stored_name)

    if encrypted_file_path.exists():
        encrypted_file_path.unlink()

    if encrypted_key_path.exists():
        encrypted_key_path.unlink()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE files
        SET status='deleted'
        WHERE stored_name=?
        """,
        (stored_name,)
    )

    changed = cursor.rowcount
    conn.commit()
    conn.close()

    return changed > 0
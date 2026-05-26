# modules/bruteforce.py

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "service" / "login.db"

MAX_FAILED_ATTEMPTS = 3
WINDOW_MINUTES = 5


def _now():
    return datetime.now()


def _parse_time(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def is_login_denied_by_status(status):
    """
    Проверяет, запрещён ли вход пользователю по статусу.
    """

    return status in ("blocked", "used")


def register_failed_login(username):
    """
    Регистрирует неудачную попытку входа.

    Если за последние WINDOW_MINUTES набрано MAX_FAILED_ATTEMPTS ошибок,
    пользователь блокируется.
    """

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT status, failed_attempts, failed_window_start
        FROM users
        WHERE username=?
        """,
        (username,)
    )

    row = cursor.fetchone()

    if row is None:
        conn.close()
        return {
            "blocked": False,
            "failed_attempts": 0
        }

    status, failed_attempts, failed_window_start = row

    if status in ("blocked", "used"):
        conn.close()
        return {
            "blocked": True,
            "failed_attempts": failed_attempts
        }

    now = _now()
    window_start = _parse_time(failed_window_start)

    # Если окна ещё не было или оно истекло — начинаем новое окно
    if window_start is None or now - window_start > timedelta(minutes=WINDOW_MINUTES):
        failed_attempts = 1
        window_start = now
    else:
        failed_attempts += 1

    should_block = failed_attempts >= MAX_FAILED_ATTEMPTS

    # Чтобы случайно не потерять доступ к демонстрации, admin не блокируем.
    if should_block and username != "admin":
        cursor.execute(
            """
            UPDATE users
            SET failed_attempts=?,
                failed_window_start=?,
                status='blocked'
            WHERE username=?
            """,
            (
                failed_attempts,
                window_start.isoformat(timespec="seconds"),
                username
            )
        )
    else:
        cursor.execute(
            """
            UPDATE users
            SET failed_attempts=?,
                failed_window_start=?
            WHERE username=?
            """,
            (
                failed_attempts,
                window_start.isoformat(timespec="seconds"),
                username
            )
        )

    conn.commit()
    conn.close()

    return {
        "blocked": should_block and username != "admin",
        "failed_attempts": failed_attempts
    }


def reset_failed_logins(username):
    """
    Сбрасывает счётчик неудачных попыток после успешного входа
    или административной разблокировки.
    """

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET failed_attempts=0,
            failed_window_start=NULL
        WHERE username=?
        """,
        (username,)
    )

    conn.commit()
    conn.close()


def unblock_user(username):
    """
    Разблокирует пользователя, заблокированного из-за перебора пароля.

    Одноразовые использованные пользователи со статусом used не разблокируются.
    """

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET status='active',
            failed_attempts=0,
            failed_window_start=NULL
        WHERE username=? AND status='blocked'
        """,
        (username,)
    )

    changed = cursor.rowcount

    conn.commit()
    conn.close()

    return changed > 0
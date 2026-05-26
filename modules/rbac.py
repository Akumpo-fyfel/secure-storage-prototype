import sqlite3

DB_PATH = "service/access.db"

ALLOWED_USER_ROLES = [
    "writer",
    "reader",
    "editor"
]

ADMIN_ROLE = "administrator"


PERMISSIONS = {
    "administrator": {
        "manage_users",
        "upload_file",
        "list_files",
        "download_file",
        "delete_file"
    },
    "editor": {
        "upload_file",
        "list_files",
        "download_file",
        "delete_file"
    },
    "reader": {
        "list_files",
        "download_file"
    },
    "writer": {
        "upload_file"
    }
}


def has_permission(username, permission):
    role = get_user_role(username)

    if role is None:
        return False

    return permission in PERMISSIONS.get(role, set())

def get_user_role(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT role FROM access_rules WHERE username=?",
        (username,)
    )

    row = cursor.fetchone()
    conn.close()

    if row:
        return row[0]

    return None


def set_user_role(username, role):
    if role == ADMIN_ROLE:
        return False

    if role not in ALLOWED_USER_ROLES:
        return False

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO access_rules (username, role)
        VALUES (?, ?)
        """,
        (username, role)
    )

    conn.commit()
    conn.close()

    return True



def delete_user_role(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM access_rules WHERE username=?",
        (username,)
    )

    conn.commit()
    conn.close()

def get_all_roles():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT username, role FROM access_rules")

    rows = cursor.fetchall()
    conn.close()

    return dict(rows)


def is_admin(username):
    return get_user_role(username) == ADMIN_ROLE

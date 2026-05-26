from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
from io import BytesIO
import sys
import os

sys.path.append(os.path.abspath("."))

from modules.auth import verify_user
from modules.users import list_users, create_user, delete_user, change_password, get_user_status, set_user_status
from modules.rbac import get_user_role, is_admin, set_user_role, delete_user_role, get_all_roles, ALLOWED_USER_ROLES, has_permission
from modules.storage import save_file, list_files, get_decrypted_file_data, get_original_filename, delete_file
from modules.audit import log_event, list_events, clear_events
from modules.crypto import rotate_master_key
from modules.bruteforce import unblock_user

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

app.secret_key = "temporary-dev-secret-key"
UPLOAD_PROGRESS = {}

@app.route("/", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = verify_user(username, password)

        if user:
            role = get_user_role(username)

            session["username"] = username
            session["role"] = role
            log_event(username, "login", "success")

            return redirect(url_for("dashboard"))

        error = "Неверный логин или пароль"
        log_event(username, "login", "failed", details="Неверный логин или пароль")

    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    user = {
        "username": session["username"],
        "role": session["role"]
    }

    return render_template("dashboard.html", user=user)


@app.route("/users", methods=["GET", "POST"])
def users_page():
    if "username" not in session:
        return redirect(url_for("login"))

    if not is_admin(session["username"]):
        return "Доступ запрещён", 403

    message = None
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role")

        if not username or not password or not role:
            error = "Логин, пароль и роль обязательны"
        elif role not in ALLOWED_USER_ROLES:
            error = "Недопустимая роль"
        else:
            status = "one_time" if request.form.get("is_one_time") == "on" else "active"
            ok = create_user(username, password, status)

            if ok:
                set_user_role(username, role)
                message = "Пользователь создан"
            else:
                error = "Пользователь уже существует"

    users = list_users()
    roles = get_all_roles()

    users_with_roles = []

    for user in users:
        user_id = user[0]
        username = user[1]
        status = user[2]
        failed_attempts = user[3]
        failed_window_start = user[4]
        role = roles.get(username, "не назначена")

        users_with_roles.append((user_id, username, role, status, failed_attempts, failed_window_start))

    return render_template(
        "users.html",
        users=users_with_roles,
        roles=ALLOWED_USER_ROLES,
        message=message,
        error=error
    )


@app.route("/delete_user", methods=["POST"])
def delete_user_route():
    if "username" not in session:
        return redirect(url_for("login"))

    if not is_admin(session["username"]):
        return "Доступ запрещён", 403

    username = request.form.get("username")

    if username != "admin":
        delete_user(username)
        delete_user_role(username)

    return redirect(url_for("users_page"))

@app.route("/change_password", methods=["POST"])
def change_password_route():
    if not is_admin(session.get("username")):
        return redirect(url_for("dashboard"))

    username = request.form.get("username")
    new_password = request.form.get("new_password")

    if username and new_password:
        change_password(username, new_password)

    return redirect(url_for("users_page"))

@app.route("/logout")
def logout():
    username = session.get("username")

    if username and get_user_status(username) == "one_time":
        set_user_status(username, "used")

        log_event(
            username,
            "one_time_user_used",
            "success",
            object_type="user",
            object_name=username,
            details="Одноразовая учётная запись использована и заблокирована для повторного входа"
        )

    session.clear()
    return redirect(url_for("login"))


@app.route("/unblock_user", methods=["POST"])
def unblock_user_route():
    if "username" not in session:
        return redirect(url_for("login"))

    admin_username = session["username"]

    if not is_admin(admin_username):
        log_event(
            admin_username,
            "user_unblock",
            "denied",
            object_type="user",
            details="Недостаточно прав для разблокировки пользователя"
        )
        return "Доступ запрещён", 403

    username = request.form.get("username")

    if not username or username == "admin":
        return redirect(url_for("users_page"))

    changed = unblock_user(username)

    log_event(
        admin_username,
        "user_unblock",
        "success" if changed else "failed",
        object_type="user",
        object_name=username,
        details="Пользователь разблокирован" if changed else "Пользователь не был разблокирован"
    )

    return redirect(url_for("users_page"))


@app.route("/files", methods=["GET", "POST"])
def files_page():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session.get("username")

    message = None
    error = None

    can_upload = has_permission(username, "upload_file")
    can_list = has_permission(username, "list_files")
    can_download = has_permission(username, "download_file")
    can_delete = has_permission(username, "delete_file")

    if request.method == "POST":
        if not can_upload:
            error = "Недостаточно прав для загрузки файлов"

            log_event(
                username,
                "file_upload",
                "denied",
                object_type="file",
                details="Недостаточно прав для загрузки файлов"
            )
        else:
            job_id = request.form.get("job_id", "default")
            uploaded_files = request.files.getlist("files")
            uploaded_files = [
                uploaded_file for uploaded_file in uploaded_files
                if uploaded_file and uploaded_file.filename
            ]

            total_files = len(uploaded_files)
            uploaded_count = 0

            UPLOAD_PROGRESS[job_id] = {
                "percent": 0,
                "message": "Начало обработки файлов"
            }

            for index, uploaded_file in enumerate(uploaded_files):
                original_name = uploaded_file.filename

                def progress_callback(file_percent, index=index, original_name=original_name):
                    if total_files == 0:
                        total_percent = 100
                    else:
                        total_percent = int(((index + file_percent / 100) / total_files) * 100)

                    UPLOAD_PROGRESS[job_id] = {
                        "percent": total_percent,
                        "message": f"Шифрование файла: {original_name}"
                    }

                stored_name = save_file(
                    uploaded_file,
                    username,
                    progress_callback=progress_callback
                )

                if stored_name:
                    uploaded_count += 1

                    log_event(
                        username,
                        "file_upload",
                        "success",
                        object_type="file",
                        object_name=original_name,
                        details=f"Файл сохранён в зашифрованном виде: {stored_name}"
                    )

            UPLOAD_PROGRESS[job_id] = {
                "percent": 100,
                "message": "Загрузка и шифрование завершены"
            }

            if uploaded_count > 0:
                message = f"Загружено файлов: {uploaded_count}"
            else:
                error = "Файлы не выбраны"

    files = []

    if can_list:
        files = list_files()

    return render_template(
        "files.html",
        files=files,
        message=message,
        error=error,
        can_upload=can_upload,
        can_list=can_list,
        can_download=can_download,
        can_delete=can_delete
    )


@app.route("/rotate_master_key", methods=["POST"])
def rotate_master_key_route():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    if not is_admin(username):
        log_event(
            username,
            "master_key_rotation",
            "denied",
            object_type="key",
            object_name="master_key",
            details="Недостаточно прав для смены мастер-ключа"
        )
        return "Доступ запрещён", 403

    try:
        result = rotate_master_key()

        log_event(
            username,
            "master_key_rotation",
            "success",
            object_type="key",
            object_name="master_key",
            details=(
                f"Выполнена смена мастер-ключа. "
                f"Перезашифровано файловых ключей: {result['rotated_file_keys']}. "
                f"Резервная копия: {result['backup_dir']}"
            )
        )

        return redirect(url_for("users_page"))

    except Exception as error:
        log_event(
            username,
            "master_key_rotation",
            "failed",
            object_type="key",
            object_name="master_key",
            details=str(error)
        )

        return f"Ошибка смены мастер-ключа: {error}", 500


@app.route("/download/<filename>")
def download_file(filename):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session.get("username")

    if not has_permission(username, "download_file"):
        
        log_event(
            username,
            "file_download",
            "denied",
            object_type="file",
            object_name=filename,
            details="Недостаточно прав для скачивания файла"
        )
        
        return redirect(url_for("files_page"))

    try:
        plain_data = get_decrypted_file_data(filename)
        original_name = get_original_filename(filename)
        
        log_event(
            username,
            "file_download",
            "success",
            object_type="file",
            object_name=original_name,
            details=f"Файл расшифрован и передан пользователю: {filename}"
        )

        return send_file(
            BytesIO(plain_data),
            as_attachment=True,
            download_name=original_name
        )

    except Exception as error:
        return f"Ошибка расшифрования файла: {error}", 500
    
    

@app.route("/delete_file", methods=["POST"])
def delete_file_route():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session.get("username")

    if not has_permission(username, "delete_file"):
        return redirect(url_for("files_page"))

    filename = request.form.get("filename")
    delete_file(filename)

    return redirect(url_for("files_page"))

@app.route("/audit")
def audit_page():
    if "username" not in session:
        return redirect(url_for("login"))

    if not is_admin(session["username"]):
        return "Доступ запрещён", 403

    events = list_events()

    return render_template("audit.html", events=events)



@app.route("/clear_audit", methods=["POST"])
def clear_audit_route():
    if "username" not in session:
        return redirect(url_for("login"))

    if not is_admin(session["username"]):
        log_event(
            session.get("username"),
            "audit_clear",
            "denied",
            details="Недостаточно прав для очистки журнала"
        )
        return "Доступ запрещён", 403

    clear_events()

    log_event(
        session["username"],
        "audit_clear",
        "success",
        details="Журнал событий очищен"
    )

    return redirect(url_for("audit_page"))


@app.route("/upload_progress/<job_id>")
def upload_progress(job_id):
    progress = UPLOAD_PROGRESS.get(job_id, {
        "percent": 0,
        "message": "Ожидание начала обработки"
    })

    return jsonify(progress)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

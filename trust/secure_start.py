# trust/secure_start.py

import json
import hmac
import hashlib
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

TRUST_DIR = BASE_DIR / "trust"
ROOT_KEY_PATH = TRUST_DIR / "root_key.bin"
MANIFEST_PATH = TRUST_DIR / "manifest.json"
MANIFEST_HMAC_PATH = TRUST_DIR / "manifest.hmac"

ROOT_KEY_SIZE = 32


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def load_root_key() -> bytes:
    if not ROOT_KEY_PATH.exists():
        raise FileNotFoundError("root_key.bin не найден. Сначала выполните init_trust.py")

    root_key = ROOT_KEY_PATH.read_bytes()

    if len(root_key) != ROOT_KEY_SIZE:
        raise ValueError("Некорректная длина root_key.bin")

    return root_key


def verify_manifest_hmac(root_key: bytes, manifest_bytes: bytes) -> bool:
    if not MANIFEST_HMAC_PATH.exists():
        raise FileNotFoundError("manifest.hmac не найден. Сначала выполните init_trust.py")

    expected_hmac = MANIFEST_HMAC_PATH.read_text(encoding="utf-8").strip()
    calculated_hmac = hmac.new(root_key, manifest_bytes, hashlib.sha256).hexdigest()

    return hmac.compare_digest(calculated_hmac, expected_hmac)


def verify_integrity() -> bool:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError("manifest.json не найден. Сначала выполните init_trust.py")

    root_key = load_root_key()
    manifest_bytes = MANIFEST_PATH.read_bytes()

    if not verify_manifest_hmac(root_key, manifest_bytes):
        print("[ERROR] Нарушена целостность manifest.json")
        return False

    manifest = json.loads(manifest_bytes.decode("utf-8"))

    if manifest.get("version") != "integrity-manifest-v1":
        print("[ERROR] Неподдерживаемая версия manifest.json")
        return False

    files = manifest.get("files", {})

    for relative_path, expected_hash in files.items():
        path = BASE_DIR / relative_path

        if not path.exists():
            print(f"[ERROR] Контролируемый файл отсутствует: {relative_path}")
            return False

        calculated_hash = sha256_file(path)

        if not hmac.compare_digest(calculated_hash, expected_hash):
            print(f"[ERROR] Нарушена целостность файла: {relative_path}")
            print(f"Expected: {expected_hash}")
            print(f"Actual:   {calculated_hash}")
            return False

    print("[OK] Контроль целостности пройден")
    return True


def start_application():
    app_path = BASE_DIR / "app" / "app.py"

    print("[OK] Запуск интерфейса защищённого носителя")
    subprocess.run([sys.executable, str(app_path)], cwd=str(BASE_DIR))


def main():
    print("Secure start initialized")
    print("Checking trusted state...")

    try:
        if not verify_integrity():
            print("Запуск заблокирован")
            sys.exit(1)

        start_application()

    except Exception as error:
        print(f"[ERROR] {error}")
        print("Запуск заблокирован")
        sys.exit(1)


if __name__ == "__main__":
    main()
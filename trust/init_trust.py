# trust/init_trust.py

import os
import json
import hmac
import hashlib
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

TRUST_DIR = BASE_DIR / "trust"
ROOT_KEY_PATH = TRUST_DIR / "root_key.bin"
MANIFEST_PATH = TRUST_DIR / "manifest.json"
MANIFEST_HMAC_PATH = TRUST_DIR / "manifest.hmac"

ROOT_KEY_SIZE = 32


CONTROLLED_PATHS = [
    "app/app.py",

    "app/templates/audit.html",
    "app/templates/dashboard.html",
    "app/templates/files.html",
    "app/templates/login.html",
    "app/templates/users.html",

    "modules/audit.py",
    "modules/auth.py",
    "modules/crypto.py",
    "modules/kuznechik.py",
    "modules/rbac.py",
    "modules/storage.py",
    "modules/users.py",
]


def get_or_create_root_key() -> bytes:
    TRUST_DIR.mkdir(parents=True, exist_ok=True)

    if ROOT_KEY_PATH.exists():
        root_key = ROOT_KEY_PATH.read_bytes()

        if len(root_key) != ROOT_KEY_SIZE:
            raise ValueError("Некорректная длина root_key.bin")

        return root_key

    root_key = os.urandom(ROOT_KEY_SIZE)
    ROOT_KEY_PATH.write_bytes(root_key)

    return root_key


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def build_manifest() -> dict:
    files = {}

    for relative_path in CONTROLLED_PATHS:
        path = BASE_DIR / relative_path

        if not path.exists():
            raise FileNotFoundError(f"Контролируемый файл не найден: {relative_path}")

        files[relative_path] = sha256_file(path)

    return {
        "version": "integrity-manifest-v1",
        "algorithm": "SHA-256 + HMAC-SHA256",
        "files": files
    }


def make_manifest_hmac(root_key: bytes, manifest_bytes: bytes) -> str:
    return hmac.new(root_key, manifest_bytes, hashlib.sha256).hexdigest()


def main():
    root_key = get_or_create_root_key()

    manifest = build_manifest()
    manifest_bytes = json.dumps(
        manifest,
        indent=4,
        sort_keys=True
    ).encode("utf-8")

    manifest_hmac = make_manifest_hmac(root_key, manifest_bytes)

    MANIFEST_PATH.write_bytes(manifest_bytes)
    MANIFEST_HMAC_PATH.write_text(manifest_hmac, encoding="utf-8")

    print("Trust manifest initialized")
    print(f"Controlled files: {len(manifest['files'])}")
    print(f"Manifest: {MANIFEST_PATH}")
    print(f"HMAC: {MANIFEST_HMAC_PATH}")


if __name__ == "__main__":
    main()
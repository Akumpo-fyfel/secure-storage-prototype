# modules/crypto.py

"""
Криптографический модуль программного прототипа.

Реализует:
- генерацию мастер-ключа прототипа;
- генерацию файловых ключей;
- шифрование данных шифром "Кузнечик" в режиме счётчика;
- защиту целостности через HMAC-SHA256;
- шифрование файлового ключа мастер-ключом.
"""

import os
import json
import hmac
import hashlib
from pathlib import Path
import shutil
from datetime import datetime

try:
    from modules.kuznechik import encrypt_block, encrypt_block_with_round_keys, expand_key, BLOCK_SIZE, KEY_SIZE
except ModuleNotFoundError:
    from kuznechik import encrypt_block, encrypt_block_with_round_keys, expand_key, BLOCK_SIZE, KEY_SIZE


BASE_DIR = Path(__file__).resolve().parent.parent

MASTER_KEY_DIR = BASE_DIR / "service" / "encrypted_master_keys"
MASTER_KEY_PATH = MASTER_KEY_DIR / "master.key"          # старый открытый ключ, нужен только для миграции
MASTER_KEY_ENC_PATH = MASTER_KEY_DIR / "master.key.enc"  # новый зашифрованный мастер-ключ

FILE_KEYS_DIR = BASE_DIR / "storage" / "encrypted_file_keys"
MASTER_KEY_BACKUP_DIR = MASTER_KEY_DIR / "rotation_backups"

TRUST_DIR = BASE_DIR / "trust"
ROOT_KEY_PATH = TRUST_DIR / "root_key.bin"

MASTER_KEY_VERSION = "encrypted-master-key-v1"


MAGIC = b"KUZ1"
DATA_VERSION = "kuznechik-ctr-hmac-v1"
KEY_VERSION = "wrapped-file-key-v1"


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _increment_counter(counter: bytes) -> bytes:
    value = int.from_bytes(counter, byteorder="big")
    value = (value + 1) % (1 << 128)
    return value.to_bytes(BLOCK_SIZE, byteorder="big")


def _kuznechik_ctr_crypt(data: bytes, key: bytes, iv: bytes, progress_callback=None) -> bytes:
    """
    Шифрование/расшифрование данных в режиме CTR.

    progress_callback(percent) вызывается во время обработки,
    чтобы веб-интерфейс мог показывать прогресс.
    """

    if len(key) != KEY_SIZE:
        raise ValueError("Ключ должен иметь длину 32 байта")

    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен иметь длину 16 байт")

    round_keys = expand_key(key)

    result = bytearray(len(data))
    counter = int.from_bytes(iv, byteorder="big")
    total_size = len(data)

    last_percent = -1

    for offset in range(0, total_size, BLOCK_SIZE):
        block = data[offset:offset + BLOCK_SIZE]

        counter_block = counter.to_bytes(BLOCK_SIZE, byteorder="big")
        gamma = encrypt_block_with_round_keys(counter_block, round_keys)

        for i in range(len(block)):
            result[offset + i] = block[i] ^ gamma[i]

        counter = (counter + 1) % (1 << 128)

        if progress_callback and total_size > 0:
            percent = int((offset + len(block)) * 100 / total_size)

            if percent != last_percent:
                progress_callback(percent)
                last_percent = percent

    return bytes(result)


def _derive_key(key: bytes, purpose: bytes) -> bytes:
    return hashlib.sha256(key + purpose).digest()


def _make_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _verify_hmac(key: bytes, data: bytes, expected_tag: bytes) -> bool:
    calculated_tag = _make_hmac(key, data)
    return hmac.compare_digest(calculated_tag, expected_tag)


def get_root_key() -> bytes:
    """
    Возвращает root key прототипа.

    В программной модели этот ключ имитирует секрет доверенной среды.
    В аппаратной реализации аналогичная функция должна выполняться TPM,
    защищённым контроллером или аппаратным корнем доверия.
    """

    TRUST_DIR.mkdir(parents=True, exist_ok=True)

    if not ROOT_KEY_PATH.exists():
        root_key = os.urandom(KEY_SIZE)
        ROOT_KEY_PATH.write_bytes(root_key)
        return root_key

    root_key = ROOT_KEY_PATH.read_bytes()

    if len(root_key) != KEY_SIZE:
        raise ValueError("Некорректная длина root key")

    return root_key


def encrypt_master_key(master_key: bytes) -> bytes:
    """
    Шифрует мастер-ключ root key.
    Возвращает JSON-пакет в байтах.
    """

    if len(master_key) != KEY_SIZE:
        raise ValueError("Мастер-ключ должен иметь длину 32 байта")

    root_key = get_root_key()

    encryption_key = _derive_key(root_key, b"master-key-encryption")
    mac_key = _derive_key(root_key, b"master-key-hmac")

    iv = os.urandom(BLOCK_SIZE)
    encrypted_master_key = _kuznechik_ctr_crypt(master_key, encryption_key, iv)

    tag_data = MASTER_KEY_VERSION.encode("utf-8") + iv + encrypted_master_key
    tag = _make_hmac(mac_key, tag_data)

    package = {
        "version": MASTER_KEY_VERSION,
        "iv": iv.hex(),
        "encrypted_master_key": encrypted_master_key.hex(),
        "tag": tag.hex()
    }

    return json.dumps(package, indent=4).encode("utf-8")


def decrypt_master_key(package_bytes: bytes) -> bytes:
    """
    Расшифровывает мастер-ключ root key.
    """

    root_key = get_root_key()

    encryption_key = _derive_key(root_key, b"master-key-encryption")
    mac_key = _derive_key(root_key, b"master-key-hmac")

    package = json.loads(package_bytes.decode("utf-8"))

    if package.get("version") != MASTER_KEY_VERSION:
        raise ValueError("Неподдерживаемая версия пакета мастер-ключа")

    iv = bytes.fromhex(package["iv"])
    encrypted_master_key = bytes.fromhex(package["encrypted_master_key"])
    tag = bytes.fromhex(package["tag"])

    tag_data = MASTER_KEY_VERSION.encode("utf-8") + iv + encrypted_master_key

    if not _verify_hmac(mac_key, tag_data, tag):
        raise ValueError("Нарушена целостность зашифрованного мастер-ключа")

    master_key = _kuznechik_ctr_crypt(encrypted_master_key, encryption_key, iv)

    if len(master_key) != KEY_SIZE:
        raise ValueError("Некорректная длина мастер-ключа")

    return master_key


def get_master_key() -> bytes:
    """
    Возвращает мастер-ключ прототипа.

    Мастер-ключ хранится в служебной области только в зашифрованном виде.
    Для защиты мастер-ключа используется root key программной модели
    доверенной среды.
    """

    MASTER_KEY_DIR.mkdir(parents=True, exist_ok=True)

    # Миграция старого открытого master.key, если он уже был создан ранее
    if MASTER_KEY_PATH.exists() and not MASTER_KEY_ENC_PATH.exists():
        plain_master_key = MASTER_KEY_PATH.read_bytes()

        if len(plain_master_key) != KEY_SIZE:
            raise ValueError("Некорректная длина старого мастер-ключа")

        encrypted_package = encrypt_master_key(plain_master_key)
        MASTER_KEY_ENC_PATH.write_bytes(encrypted_package)

        MASTER_KEY_PATH.unlink()

        return plain_master_key

    # Обычный режим: читаем зашифрованный мастер-ключ
    if MASTER_KEY_ENC_PATH.exists():
        encrypted_package = MASTER_KEY_ENC_PATH.read_bytes()
        return decrypt_master_key(encrypted_package)

    # Первичная инициализация
    master_key = os.urandom(KEY_SIZE)
    encrypted_package = encrypt_master_key(master_key)
    MASTER_KEY_ENC_PATH.write_bytes(encrypted_package)

    return master_key


def wrap_file_key_with_master_key(file_key: bytes, master_key: bytes) -> bytes:
    """
    Шифрует файловый ключ указанным мастер-ключом.
    Используется при обычной записи файла и при смене мастер-ключа.
    """

    if len(file_key) != KEY_SIZE:
        raise ValueError("Файловый ключ должен иметь длину 32 байта")

    if len(master_key) != KEY_SIZE:
        raise ValueError("Мастер-ключ должен иметь длину 32 байта")

    encryption_key = _derive_key(master_key, b"file-key-encryption")
    mac_key = _derive_key(master_key, b"file-key-hmac")

    iv = os.urandom(BLOCK_SIZE)
    wrapped_key = _kuznechik_ctr_crypt(file_key, encryption_key, iv)

    tag_data = KEY_VERSION.encode("utf-8") + iv + wrapped_key
    tag = _make_hmac(mac_key, tag_data)

    package = {
        "version": KEY_VERSION,
        "iv": iv.hex(),
        "wrapped_key": wrapped_key.hex(),
        "tag": tag.hex()
    }

    return json.dumps(package, indent=4).encode("utf-8")


def unwrap_file_key_with_master_key(wrapped_file_key: bytes, master_key: bytes) -> bytes:
    """
    Расшифровывает файловый ключ указанным мастер-ключом.
    Используется при обычном чтении файла и при смене мастер-ключа.
    """

    if len(master_key) != KEY_SIZE:
        raise ValueError("Мастер-ключ должен иметь длину 32 байта")

    encryption_key = _derive_key(master_key, b"file-key-encryption")
    mac_key = _derive_key(master_key, b"file-key-hmac")

    package = json.loads(wrapped_file_key.decode("utf-8"))

    if package.get("version") != KEY_VERSION:
        raise ValueError("Неподдерживаемая версия пакета файлового ключа")

    iv = bytes.fromhex(package["iv"])
    encrypted_file_key = bytes.fromhex(package["wrapped_key"])
    tag = bytes.fromhex(package["tag"])

    tag_data = KEY_VERSION.encode("utf-8") + iv + encrypted_file_key

    if not _verify_hmac(mac_key, tag_data, tag):
        raise ValueError("Нарушена целостность зашифрованного файлового ключа")

    file_key = _kuznechik_ctr_crypt(encrypted_file_key, encryption_key, iv)

    if len(file_key) != KEY_SIZE:
        raise ValueError("Некорректная длина файлового ключа")

    return file_key


def wrap_file_key(file_key: bytes) -> bytes:
    """
    Шифрует файловый ключ текущим мастер-ключом системы.
    """

    master_key = get_master_key()
    return wrap_file_key_with_master_key(file_key, master_key)


def unwrap_file_key(wrapped_file_key: bytes) -> bytes:
    """
    Расшифровывает файловый ключ текущим мастер-ключом системы.
    """

    master_key = get_master_key()
    return unwrap_file_key_with_master_key(wrapped_file_key, master_key)



def encrypt_file_data(plain_data: bytes, progress_callback=None) -> tuple[bytes, bytes]:
    """
    Шифрует содержимое файла.

    Возвращает:
    - encrypted_data: зашифрованное содержимое файла;
    - wrapped_file_key: зашифрованный файловый ключ.
    """

    file_key = os.urandom(KEY_SIZE)

    encryption_key = _derive_key(file_key, b"file-data-encryption")
    mac_key = _derive_key(file_key, b"file-data-hmac")

    iv = os.urandom(BLOCK_SIZE)
    ciphertext = _kuznechik_ctr_crypt(
        plain_data,
        encryption_key,
        iv,
        progress_callback=progress_callback
    )

    tag_data = DATA_VERSION.encode("utf-8") + iv + ciphertext
    tag = _make_hmac(mac_key, tag_data)

    encrypted_data = MAGIC + iv + tag + ciphertext
    wrapped_file_key = wrap_file_key(file_key)

    return encrypted_data, wrapped_file_key


def decrypt_file_data(encrypted_data: bytes, wrapped_file_key: bytes) -> bytes:
    """
    Расшифровывает содержимое файла.
    """

    if len(encrypted_data) < len(MAGIC) + BLOCK_SIZE + 32:
        raise ValueError("Некорректный формат зашифрованного файла")

    if encrypted_data[:len(MAGIC)] != MAGIC:
        raise ValueError("Некорректная сигнатура зашифрованного файла")

    file_key = unwrap_file_key(wrapped_file_key)

    encryption_key = _derive_key(file_key, b"file-data-encryption")
    mac_key = _derive_key(file_key, b"file-data-hmac")

    offset = len(MAGIC)

    iv = encrypted_data[offset:offset + BLOCK_SIZE]
    offset += BLOCK_SIZE

    tag = encrypted_data[offset:offset + 32]
    offset += 32

    ciphertext = encrypted_data[offset:]

    tag_data = DATA_VERSION.encode("utf-8") + iv + ciphertext

    if not _verify_hmac(mac_key, tag_data, tag):
        raise ValueError("Нарушена целостность зашифрованного файла")

    plain_data = _kuznechik_ctr_crypt(ciphertext, encryption_key, iv)

    return plain_data


def rotate_master_key() -> dict:
    """
    Выполняет смену мастер-ключа системы без повторного шифрования пользовательских файлов.

    Алгоритм:
    1. Получить текущий мастер-ключ.
    2. Расшифровать все файловые ключи старым мастер-ключом.
    3. Сформировать новый мастер-ключ.
    4. Зашифровать все файловые ключи новым мастер-ключом.
    5. Зашифровать новый мастер-ключ root key доверенной среды.
    6. Заменить master.key.enc и файлы *.key.
    """

    MASTER_KEY_DIR.mkdir(parents=True, exist_ok=True)
    FILE_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    MASTER_KEY_BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    old_master_key = get_master_key()

    key_files = sorted(FILE_KEYS_DIR.glob("*.key"))

    file_keys = {}

    # 1. Сначала расшифровываем все файловые ключи старым мастер-ключом
    for key_path in key_files:
        wrapped_file_key = key_path.read_bytes()
        file_key = unwrap_file_key_with_master_key(wrapped_file_key, old_master_key)
        file_keys[key_path] = file_key

    # 2. Генерируем новый мастер-ключ
    new_master_key = os.urandom(KEY_SIZE)

    # 3. Готовим новые зашифрованные файловые ключи в памяти
    new_wrapped_file_keys = {}

    for key_path, file_key in file_keys.items():
        new_wrapped_file_keys[key_path] = wrap_file_key_with_master_key(
            file_key,
            new_master_key
        )

    # 4. Готовим новый зашифрованный master.key.enc
    new_encrypted_master_key = encrypt_master_key(new_master_key)

    # 5. Создаём резервную копию текущих ключевых материалов
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = MASTER_KEY_BACKUP_DIR / f"rotation_{timestamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    if MASTER_KEY_ENC_PATH.exists():
        shutil.copy2(
            MASTER_KEY_ENC_PATH,
            backup_dir / "master.key.enc.bak"
        )

    keys_backup_dir = backup_dir / "encrypted_file_keys"
    keys_backup_dir.mkdir(parents=True, exist_ok=True)

    for key_path in key_files:
        shutil.copy2(
            key_path,
            keys_backup_dir / key_path.name
        )

    # 6. Сначала записываем новые файловые ключи во временные файлы
    temp_key_paths = []

    for key_path, new_wrapped_key in new_wrapped_file_keys.items():
        temp_path = key_path.with_suffix(key_path.suffix + ".tmp")
        temp_path.write_bytes(new_wrapped_key)
        temp_key_paths.append((temp_path, key_path))

    temp_master_key_path = MASTER_KEY_ENC_PATH.with_suffix(".key.enc.tmp")
    temp_master_key_path.write_bytes(new_encrypted_master_key)

    # 7. Атомарно заменяем файлы ключей
    for temp_path, key_path in temp_key_paths:
        temp_path.replace(key_path)

    # 8. Заменяем зашифрованный мастер-ключ
    temp_master_key_path.replace(MASTER_KEY_ENC_PATH)

    return {
        "status": "success",
        "rotated_file_keys": len(key_files),
        "backup_dir": str(backup_dir)
    }

def self_test() -> bool:
    plain_data = b"Test data for secure USB prototype. Kuznechik encryption check."

    encrypted_data, wrapped_file_key = encrypt_file_data(plain_data)
    decrypted_data = decrypt_file_data(encrypted_data, wrapped_file_key)

    return decrypted_data == plain_data and encrypted_data != plain_data


if __name__ == "__main__":
    if self_test():
        print("Crypto self-test: OK")
    else:
        print("Crypto self-test: FAILED")
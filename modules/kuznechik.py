# modules/kuznechik.py

"""
Реализация блочного шифра "Кузнечик" для программного прототипа.

Блок: 16 байт.
Ключ: 32 байта.
"""

BLOCK_SIZE = 16
KEY_SIZE = 32


PI = [
    252, 238, 221, 17, 207, 110, 49, 22,
    251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186,
    23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33,
    129, 28, 60, 66, 139, 1, 142, 79,
    5, 132, 2, 174, 227, 106, 143, 160,
    6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171,
    242, 42, 104, 162, 253, 58, 206, 204,
    181, 112, 14, 86, 8, 12, 118, 18,
    191, 114, 19, 71, 156, 183, 93, 135,
    21, 161, 150, 41, 16, 123, 154, 199,
    243, 145, 120, 111, 157, 158, 178, 177,
    50, 117, 25, 61, 255, 53, 138, 126,
    109, 84, 198, 128, 195, 189, 13, 87,
    223, 245, 36, 169, 62, 168, 67, 201,
    215, 121, 214, 246, 124, 34, 185, 3,
    224, 15, 236, 222, 122, 148, 176, 188,
    220, 232, 40, 80, 78, 51, 10, 74,
    167, 151, 96, 115, 30, 0, 98, 68,
    26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47,
    140, 163, 165, 125, 105, 213, 149, 59,
    7, 88, 179, 64, 134, 172, 29, 247,
    48, 55, 107, 228, 136, 217, 231, 137,
    225, 27, 131, 73, 76, 63, 248, 254,
    141, 83, 170, 144, 202, 216, 133, 97,
    32, 113, 103, 164, 45, 43, 9, 91,
    203, 155, 37, 208, 190, 229, 108, 82,
    89, 166, 116, 210, 230, 244, 180, 192,
    209, 102, 175, 194, 57, 75, 99, 182
]

INV_PI = [0] * 256
for i, value in enumerate(PI):
    INV_PI[value] = i


L_VEC = [
    148, 32, 133, 16,
    194, 192, 1, 251,
    1, 192, 194, 16,
    133, 32, 148, 1
]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _gf_mul(a: int, b: int) -> int:
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        high_bit = a & 0x80
        a = (a << 1) & 0xFF

        if high_bit:
            a ^= 0xC3

        b >>= 1

    return result


def _s(data: bytes) -> bytes:
    return bytes(PI[x] for x in data)


def _s_inv(data: bytes) -> bytes:
    return bytes(INV_PI[x] for x in data)


def _r(data: bytes) -> bytes:
    x = 0

    for i in range(BLOCK_SIZE):
        x ^= _gf_mul(data[i], L_VEC[i])

    return bytes([x]) + data[:15]


def _r_inv(data: bytes) -> bytes:
    x = data[0]

    for i in range(15):
        x ^= _gf_mul(data[i + 1], L_VEC[i])

    return data[1:] + bytes([x])


def _l(data: bytes) -> bytes:
    result = data

    for _ in range(BLOCK_SIZE):
        result = _r(result)

    return result


def _l_inv(data: bytes) -> bytes:
    result = data

    for _ in range(BLOCK_SIZE):
        result = _r_inv(result)

    return result


def _iter_constant(i: int) -> bytes:
    value = bytearray(BLOCK_SIZE)
    value[15] = i
    return _l(bytes(value))


def _f(k1: bytes, k2: bytes, c: bytes) -> tuple[bytes, bytes]:
    temp = _xor_bytes(k1, c)
    temp = _s(temp)
    temp = _l(temp)
    temp = _xor_bytes(temp, k2)

    return temp, k1


def expand_key(master_key: bytes) -> list[bytes]:
    if len(master_key) != KEY_SIZE:
        raise ValueError("Ключ Кузнечика должен иметь длину 32 байта")

    k1 = master_key[:16]
    k2 = master_key[16:]

    round_keys = [k1, k2]

    for group in range(4):
        for i in range(8):
            c = _iter_constant(group * 8 + i + 1)
            k1, k2 = _f(k1, k2, c)

        round_keys.append(k1)
        round_keys.append(k2)

    return round_keys


def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен иметь длину 16 байт")

    round_keys = expand_key(key)
    state = block

    for i in range(9):
        state = _xor_bytes(state, round_keys[i])
        state = _s(state)
        state = _l(state)

    state = _xor_bytes(state, round_keys[9])

    return state

def encrypt_block_with_round_keys(block, round_keys):
    """
    Шифрует один блок Кузнечиком с уже подготовленными раундовыми ключами.
    Используется для ускорения CTR-режима.
    """

    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен иметь длину 16 байт")

    if len(round_keys) != 10:
        raise ValueError("Некорректное количество раундовых ключей")

    state = block

    for i in range(9):
        state = _xor_bytes(state, round_keys[i])
        state = _s(state)
        state = _l(state)

    state = _xor_bytes(state, round_keys[9])

    return state

def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок должен иметь длину 16 байт")

    round_keys = expand_key(key)
    state = _xor_bytes(block, round_keys[9])

    for i in range(8, -1, -1):
        state = _l_inv(state)
        state = _s_inv(state)
        state = _xor_bytes(state, round_keys[i])

    return state


def self_test() -> bool:
    key = bytes.fromhex(
        "8899aabbccddeeff0011223344556677"
        "fedcba98765432100123456789abcdef"
    )

    plaintext = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
    expected_ciphertext = bytes.fromhex("7f679d90bebc24305a468d42b9d4edcd")

    ciphertext = encrypt_block(plaintext, key)
    decrypted = decrypt_block(ciphertext, key)

    return ciphertext == expected_ciphertext and decrypted == plaintext


if __name__ == "__main__":
    if self_test():
        print("Kuznechik self-test: OK")
    else:
        print("Kuznechik self-test: FAILED")
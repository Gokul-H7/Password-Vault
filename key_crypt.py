import os
import json
import hmac
import hashlib
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# 1. KEY DERIVATION FUNCTION (NOW RETURNS 64 BYTES)
def derive_key(master_password: str, salt: bytes):
    return low_level.hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=64,  # 64 bytes (32 for AES + 32 for HMAC)
        type=low_level.Type.ID
    )


# 2. SPLIT MASTER KEY INTO AES + HMAC KEYS
def split_keys(master_key: bytes):
    aes_key = master_key[:32]
    hmac_key = master_key[32:]
    return aes_key, hmac_key


# 3. ENCRYPTION FUNCTION (AES-256-GCM)
def encrypt_data(key: bytes, plaintext: str):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext


# 4. DECRYPTION FUNCTION
def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


# 5. CALCULATE HMAC FOR ENTIRE VAULT
def calculate_hmac(hmac_key: bytes, data: dict):
    # Make a copy so we don't include the HMAC itself
    data_copy = data.copy()
    data_copy.pop("hmac", None)

    # Canonical JSON (consistent ordering)
    canonical_json = json.dumps(
        data_copy,
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    return hmac.new(hmac_key, canonical_json, hashlib.sha256).hexdigest()


# 6. VERIFY HMAC
def verify_hmac(hmac_key: bytes, data: dict):
    stored_hmac = data.get("hmac")

    if stored_hmac is None:
        return False

    expected_hmac = calculate_hmac(hmac_key, data)

    return hmac.compare_digest(stored_hmac, expected_hmac)


# test code (actual executable is main.py)
if __name__ == "__main__":
    my_password = "my-secret-master-password"
    my_salt = os.urandom(16) # test value (saved in vault for real use)
    
    # Derive Key
    key = derive_key(my_password, my_salt)
    print(f"Derived Key (hex): {key.hex()}")

    # Encrypt something
    n, c = encrypt_data(key, "SecretAccountPassword123!")
    print(f"Ciphertext: {c.hex()}")

    # Decrypt it back
    decrypted = decrypt_data(key, n, c)
    print(f"Decrypted: {decrypted}")
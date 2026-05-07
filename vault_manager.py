import os
import json
import base64
from key_crypt import calculate_hmac, verify_hmac

VAULT_DIR = "vaults"


def get_vault_path(username):
    if not os.path.exists(VAULT_DIR):
        os.makedirs(VAULT_DIR)
    return os.path.join(VAULT_DIR, f"{username}_vault.json")


# SAVE VAULT (NOW WITH HMAC)
def save_vault(username, salt, entries, hmac_key):
    filepath = get_vault_path(username)

    data = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "entries": {}
    }

    for account, crypto_stuff in entries.items():
        data["entries"][account] = {
            "username": crypto_stuff.get("username", "N/A"),
            "nonce": base64.b64encode(
                crypto_stuff["nonce"]
            ).decode("utf-8"),
            "ciphertext": base64.b64encode(
                crypto_stuff["ciphertext"]
            ).decode("utf-8")
        }

    # ADD HMAC BEFORE SAVING
    data["hmac"] = calculate_hmac(hmac_key, data)

    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)


# LOAD VAULT (OPTIONAL HMAC VERIFICATION)
def load_vault(username, hmac_key=None):
    filepath = get_vault_path(username)

    if not os.path.exists(filepath):
        return None

    with open(filepath, "r") as f:
        data = json.load(f)

    # VERIFY HMAC IF KEY IS PROVIDED
    if hmac_key is not None:
        if not verify_hmac(hmac_key, data):
            raise Exception("Vault HMAC verification failed")

    salt = base64.b64decode(data["salt"])

    entries = {}
    for account, crypto_stuff in data["entries"].items():
        # Load the 'username' back into the dictionary
        entries[account] = {
            "username": crypto_stuff.get("username", "N/A"),
            "nonce": base64.b64decode(
                crypto_stuff["nonce"]
            ),
            "ciphertext": base64.b64decode(
                crypto_stuff["ciphertext"]
            )
        }

    return salt, entries
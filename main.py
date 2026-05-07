import time
import pyperclip
import sys
import os
import getpass

from key_crypt import derive_key, split_keys, encrypt_data, decrypt_data
from vault_manager import save_vault, load_vault


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def main():
    clear_screen()
    print("--- Secure Password Vault CLI ---")

    username = input("Enter Username: ").strip()
    master_pwd = getpass.getpass("Enter Master Password: ")

    # 1. LOAD OR CREATE VAULT
    vault_data = load_vault(username)

    if vault_data is None:
        print(f"No vault found for {username}. Creating new vault...")

        salt = os.urandom(16)

        # Derive 64-byte master key, then split into AES key + HMAC key
        master_key = derive_key(master_pwd, salt)
        key, hmac_key = split_keys(master_key)

        # Create hidden canary entry to verify password later
        c_nonce, c_ciphertext = encrypt_data(key, "canary_verified")

        entries = {
            "__canary__": {
                "username": "system",
                "nonce": c_nonce,
                "ciphertext": c_ciphertext
            }
        }

        save_vault(username, salt, entries, hmac_key)
        print("Vault created successfully!")

    else:
        # First load gets salt so we can derive the HMAC key
        salt, entries = vault_data

        print("Deriving key... (Memory-hard operation)")

        master_key = derive_key(master_pwd, salt)
        key, hmac_key = split_keys(master_key)

        # Reload vault with HMAC verification
        try:
            salt, entries = load_vault(username, hmac_key)
        except Exception:
            print("Vault integrity check failed. File may have been tampered with.")
            sys.exit()

        # Canary test verifies master password
        try:
            canary = entries["__canary__"]
            decrypt_data(key, canary["nonce"], canary["ciphertext"])
            print("Login Successful!")
        except Exception:
            print("Invalid Master Password or corrupted vault.")
            sys.exit()

    # 2. MAIN COMMAND LOOP
    while True:
        print(f"\n[Vault: {username}] | Commands: list, add, delete, get, exit")
        choice = input("> ").lower().strip()

        if choice == "list":
            display_entries = {
                k: v for k, v in entries.items()
                if k != "__canary__"
            }

            if not display_entries:
                print("Vault is empty.")
            else:
                print("\nStored Credentials:")
                print(f"{'Service':<20} | {'Username':<20}")
                print("-" * 45)

                for service, data in display_entries.items():
                    uname = data.get("username", "N/A")
                    print(f"{service:<20} | {uname:<20}")

        elif choice == "add":
            service = input("Service: ").strip()

            if service == "__canary__":
                print("Reserved name. Use another.")
                continue

            uname = input("Username/Email: ").strip()
            pwd = getpass.getpass("Password: ")

            nonce, ciphertext = encrypt_data(key, pwd)

            entries[service] = {
                "username": uname,
                "nonce": nonce,
                "ciphertext": ciphertext
            }

            save_vault(username, salt, entries, hmac_key)
            print(f"Added {service} ({uname}) to vault.")

        elif choice == "get":
            service = input("Enter service name: ").strip()

            if service in entries and service != "__canary__":
                data = entries[service]

                try:
                    plaintext = decrypt_data(
                        key,
                        data["nonce"],
                        data["ciphertext"]
                    )

                    print(f"Username: {data.get('username', 'N/A')}")
                    pyperclip.copy(plaintext)

                    print(f"Password for {service} copied to clipboard.")
                    print("Clearing in 10 seconds...")

                    time.sleep(10)

                    pyperclip.copy("")
                    print("Clipboard cleared.")

                except Exception:
                    print("Decryption failed. Potential tampering detected.")
            else:
                print("Account not found.")

        elif choice == "delete":
            service = input("Enter service name to delete: ").strip()

            if service == "__canary__":
                print("Cannot delete system entry.")
                continue

            if service in entries:
                del entries[service]
                save_vault(username, salt, entries, hmac_key)
                print(f"{service} deleted.")
            else:
                print("Service not found.")

        elif choice == "exit":
            print("Securely closing vault. Goodbye!")
            break

        else:
            print("Unknown command. Use: list, add, get, exit")


if __name__ == "__main__":
    main()
from argon2 import PasswordHasher

# Initialize the hasher with the parameters
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

# Test Password
mp = "test_password_abc10234"

# 1. Hashing (vault creation)
hash_str = ph.hash(mp)
print(f"Stored Hash Format: {hash_str}")

# 2. Verification (vault login)
try:
    ph.verify(hash_str, mp)
    print("Access Granted!")
except Exception:
    print("Access Denied!")
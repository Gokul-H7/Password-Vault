from argon2 import PasswordHasher

# Master Password setup
ph = PasswordHasher(
    time_cost=3,      # Number of iterations
    memory_cost=65536, # 64MB of RAM
    parallelism=4,    # Degree of parallelism
    hash_len=32       # Key size for AES-256
)

password = "my-super-secure-master-password"
hash_value = ph.hash(password)

print(f"Argon2id Hash: {hash_value}")

# To verify later during 'login'
try:
    ph.verify(hash_value, password)
    print("Authentication Successful!")
except:
    print("Authentication Failed!")
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def generate_key():
    return os.urandom(32)

def generate_iv():
    return os.urandom(16)

def aes_encrypt(key, iv, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def aes_decrypt(key, iv, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

if __name__ == "__main__":
    print("Crypto Project: SHA-256 + AES")
    message = input("Enter a message: ").encode()

    original_hash = sha256_hash(message)
    print(f"Original SHA-256: {original_hash}")

    key = generate_key()
    iv = generate_iv()

    ciphertext = aes_encrypt(key, iv, message)
    print(f"Encrypted (hex): {ciphertext.hex()}")

    decrypted = aes_decrypt(key, iv, ciphertext)
    print(f"Decrypted message: {decrypted.decode()}")

    decrypted_hash = sha256_hash(decrypted)
    print(f"Decrypted SHA-256: {decrypted_hash}")

    if original_hash == decrypted_hash:
        print("✅ Integrity check passed!")
    else:
        print("❌ Integrity check failed!")

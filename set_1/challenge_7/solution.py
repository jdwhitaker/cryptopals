from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def decrypt_ecb(ciphertext, key):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.ECB()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
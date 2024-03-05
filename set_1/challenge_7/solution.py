from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def decrypt_ecb(ciphertext, key):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.ECB()
    ).decryptor()
    output = decryptor.update(ciphertext) + decryptor.finalize()
    padding = output[-1]
    output = output[:-padding]
    return output
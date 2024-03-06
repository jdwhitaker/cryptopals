from ..challenge_9.solution import pkcs7_padding
from ...set_1.challenge_7.solution import decrypt_ecb
from ...set_1.challenge_6.solution import to_blocks
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def aes_ecb_encrypt(input, key):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.ECB()
    ).encryptor()
    output = encryptor.update(input) + encryptor.finalize()
    print(output)
    return output

def aes_cbc_decrypt(ciphertext, key, iv):
    print("aes_cbc_decrypt", ciphertext, key, iv)
    blocks = to_blocks(ciphertext, len(key))
    print(blocks)
    output = []
    prior_ciphertext = iv
    for block in blocks:
        print(block)
        plaintext = decrypt_ecb(block, key)
        print(plaintext)
        plaintext = bytes([a ^ b for a, b in zip(plaintext, prior_ciphertext)])
        print(plaintext)
        prior_ciphertext = block
        output.append(plaintext)
    return b"".join(output)

def aes_cbc_encrypt(input, key, iv):
    print("aes_cbc_encrypt", input, key, iv)
    blocks = to_blocks(input, len(key))
    print(blocks)
    output = []
    prior_ciphertext = iv
    for block in blocks:
        print(block)
        block = pkcs7_padding(block, len(key))
        block = bytes([a ^ b for a, b in zip(block, prior_ciphertext)])
        print(block)
        ciphertext = aes_ecb_encrypt(block, key)
        print(ciphertext)
        prior_ciphertext = ciphertext
        output.append(ciphertext)
    return b"".join(output)
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
    return output

def aes_cbc_decrypt(ciphertext, key, iv):
    blocks = to_blocks(ciphertext, len(key))
    output = []
    prior_ciphertext = iv
    for block in blocks:
        plaintext = decrypt_ecb(block, key)
        assert len(plaintext) == len(prior_ciphertext)
        plaintext = bytes([a ^ b for a, b in zip(plaintext, prior_ciphertext)])
        prior_ciphertext = block
        output.append(plaintext)
    return b"".join(output)

def aes_cbc_encrypt(input, key, iv):
    blocks = to_blocks(input, len(key))
    output = []
    prior_ciphertext = iv
    for block in blocks:
        assert len(block) == len(prior_ciphertext)
        block = bytes([a ^ b for a, b in zip(block, prior_ciphertext)])
        ciphertext = aes_ecb_encrypt(block, key)
        prior_ciphertext = ciphertext
        output.append(ciphertext)
    return b"".join(output)
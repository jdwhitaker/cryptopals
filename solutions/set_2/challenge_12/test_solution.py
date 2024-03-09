from .solution import aes_128_ecb, get_block_length, crack_ecb
from ..challenge_11.solution import classify_ecb_cbc
from ...set_1.challenge_6.solution import base64_decode

def test_solution():
    plaintext_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    plaintext = base64_decode(plaintext_b64)
    block_length = get_block_length(plaintext)
    print(block_length)
    ciphertext = aes_128_ecb(b'A'*1000, plaintext)
    algo = classify_ecb_cbc(ciphertext)
    assert algo == "ecb"
    cracked = crack_ecb(plaintext, block_length)
    assert cracked == base64_decode(plaintext_b64)
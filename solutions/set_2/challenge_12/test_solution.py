from .solution import aes_128_ecb_oracle, get_block_length, crack_ecb, plaintext
from ..challenge_11.solution import classify_ecb_cbc

def test_solution():
    block_length = get_block_length()
    print(block_length)
    ciphertext = aes_128_ecb_oracle(b'A'*1000)
    algo = classify_ecb_cbc(ciphertext)
    assert algo == "ecb"
    cracked = crack_ecb(block_length)
    assert cracked == plaintext
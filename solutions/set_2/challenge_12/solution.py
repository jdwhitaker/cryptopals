import random
from ..challenge_9.solution import pkcs7_padding
from ..challenge_10.solution import aes_cbc_encrypt
from ..challenge_10.solution import aes_ecb_encrypt
from ...set_1.challenge_6.solution import mean_hamming_score, to_blocks
from ...set_1.challenge_6.solution import base64_decode

plaintext_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
plaintext = base64_decode(plaintext_b64)

key = None
random.seed(0)

def get_random_aes_key():
    global key
    if key == None:
        key = random.randbytes(16)
    return key

def aes_128_ecb(chosen_string, plaintext):
    input = chosen_string + plaintext
    input = pkcs7_padding(input, 16)
    key = get_random_aes_key()
    output = aes_ecb_encrypt(input, key)
    return output

def aes_128_ecb_oracle(chosen_string):
    return aes_128_ecb(chosen_string, plaintext)

def get_block_length():
    prior_length = len(aes_128_ecb_oracle(b''))
    first = True
    block_length = 0
    i = 1
    while True:
        chosen_text = b"A"*i
        ciphertext = aes_128_ecb_oracle(chosen_text)
        length = len(ciphertext)
        if not first and prior_length != length:
            return block_length + 1
        if prior_length == length:
            block_length += 1
        else:
            first = False
            block_length = 0
        prior_length = length
        i += 1

def crack_ecb(block_length):
    cracked = []
    offset = 0
    while True:
        iblock = offset // block_length
        ibyte = offset % block_length
        print(iblock, ibyte)
        lookup = {}
        prefix = b"A"*(block_length-ibyte-1)
        for i in range(256):
            value = prefix + bytes(cracked) + bytes([i])
            key = aes_128_ecb_oracle(value)[block_length*iblock:block_length*(iblock+1)]
            lookup[key] = value
        print("prefix:", prefix)
        ciphertext = aes_128_ecb_oracle(prefix)
        output = ciphertext[block_length*iblock:block_length*(iblock+1)]
        print(f"output ({len(output)}): {output}")
        if not output in lookup:
            return bytes(cracked)[:-cracked[-1]]
        c = lookup[output][-1]
        print("cracked byte:", c)
        cracked.append(c)
        print("cracked:", bytes(cracked))
        print()
        offset += 1
        print(offset, len(ciphertext))
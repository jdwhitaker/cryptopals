import cryptopals

AES_KEY = cryptopals.get_aes_key()


def aes_128_ecb(chosen_string, plaintext, key):
    input = chosen_string + plaintext
    input = cryptopals.pkcs7_padding(input, 16)
    output = cryptopals.aes_ecb_encrypt(input, key)
    return output

def aes_128_ecb_oracle(chosen_string, plaintext):
    return aes_128_ecb(chosen_string, plaintext, AES_KEY)

def get_block_length(plaintext):
    prior_length = len(aes_128_ecb_oracle(b'', plaintext))
    first = True
    block_length = 0
    i = 1
    while True:
        chosen_text = b"A"*i
        ciphertext = aes_128_ecb_oracle(chosen_text, plaintext)
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

def crack_ecb(block_length, plaintext):
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
            key = aes_128_ecb_oracle(value, plaintext)[block_length*iblock:block_length*(iblock+1)]
            lookup[key] = value
        print("prefix:", prefix)
        ciphertext = aes_128_ecb_oracle(prefix, plaintext)
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

def test_solution():
    plaintext_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    plaintext = cryptopals.base64_decode(plaintext_b64)
    block_length = get_block_length(plaintext)
    print(block_length)
    ciphertext = aes_128_ecb_oracle(b'A'*1000, plaintext)
    algo = cryptopals.classify_ecb_cbc(ciphertext)
    assert algo == "ecb"
    cracked = crack_ecb(block_length, plaintext)
    assert cracked == plaintext
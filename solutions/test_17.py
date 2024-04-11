import cryptopals
import random

random.seed(0)
AES_KEY = cryptopals.get_aes_key()
strings = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
]

def generate_cbc_ciphertext():
    random.shuffle(strings)
    s = strings[0]
    #s = cryptopals.base64_decode(s)
    input = cryptopals.pkcs7_padding(s, 16)
    print('Plaintext:', input)
    iv = random.randbytes(16)
    ciphertext = cryptopals.aes_cbc_encrypt(input, AES_KEY, iv)
    return (ciphertext, iv)

def validate_ciphertext(ciphertext, iv):
    try:
        plaintext = cryptopals.aes_cbc_decrypt(ciphertext, AES_KEY, iv)
        plaintext = cryptopals.pkcs7_unpad(plaintext)
        return True
    except Exception as e:
        return False

def test_solution0():
    for _ in range(1, 100):
        ciphertext, iv = generate_cbc_ciphertext()
        validity = validate_ciphertext(ciphertext, iv)
        assert validity == True

def crack_cbc_padding_oracle(ciphertext, oracle):
    keylength = 16
    blocklength = 16
    out = [0 for _ in range(len(ciphertext))]
    # TODO: refactor idx into being a descending index of the cracked byte
    for idx in range(len(ciphertext) - keylength):
        end = len(ciphertext) - ((idx // 16) * 16)
        #print("ciphertext end:", end)
        bitflip_idx = len(ciphertext) - keylength - idx - 1
        plaintext_idx = len(ciphertext) - idx - 1
        pad_value = keylength - (bitflip_idx % keylength)
        # bitflip_idx % 16 == 15: [ 0x01 ]
        # bitflip_idx % 16 == 14: [ 0x02 ] 0x02
        # ...
        # bitflip_idx % 16 == 0: [0x10 ] (0x10 * 15)
        #print(bitflip_idx, '/', len(ciphertext))
        #print(f'pad_value: {pad_value}')
        validity = set()
        for b in range(0, 256):
            ct = [ciphertext[i] for i in range(len(ciphertext))]
            ct[bitflip_idx] = ciphertext[bitflip_idx] ^ b
            # set the rest of the padding 
            for i in range(pad_value-1):
                new_value = ct[bitflip_idx + i + 1] ^ out[plaintext_idx + i + 1] ^ pad_value
                ct[bitflip_idx + i + 1] = new_value
                #print(f"ct[{bitflip_idx + i + 1}] = {hex(new_value)}")
            ct = bytes(ct)
            valid = oracle(ct[:end])
            if valid:
                validity.add(b)
        #print(f'validity: {validity}')
        # break any coincidental longer pad matches (0x0202)
        validity2 = set()
        for b in range(0, 256):
            ct = [ciphertext[i] for i in range(len(ciphertext))]
            ct[bitflip_idx] = ciphertext[bitflip_idx] ^ b
            # set the rest of the padding 
            for i in range(pad_value-1):
                new_value = ct[bitflip_idx + i + 1] ^ out[plaintext_idx + i + 1] ^ pad_value
                ct[bitflip_idx + i + 1] = new_value
                #print(f"ct[{bitflip_idx + i + 1}] = {hex(new_value)}")
            ct[bitflip_idx-1] = ciphertext[bitflip_idx-1] ^ 0xFF
            ct = bytes(ct)
            valid = oracle(ct[:end])
            if valid:
                validity2.add(b)
        validity = validity.intersection(validity2)
        try:
            assert len(validity) == 1
        except:
            print(f"{len(validity)} valid bytes found")
            return None
        # b: the byte we xor'd the ciphertext with to result in a valid ciphertext
        # c: the character of the plaintext we are decrypting
        # b ^ c = 0x01
        # b ^ c ^ b = 0x01 ^ b
        # c = 0x01 ^ b
        c = pad_value ^ validity.pop()
        #print(bytes([c]))
        out[bitflip_idx + keylength] = c
        #print(bytes(out))
        #print('--')
    return bytes(out)

def test_solution():
    decoded = [cryptopals.base64_decode(str(i[16:], encoding='ascii')) for i in strings]
    ciphertext, iv = generate_cbc_ciphertext()
    cracked = crack_cbc_padding_oracle(ciphertext, lambda c: validate_ciphertext(c, iv))
    cracked = cracked[16:]
    cracked = cryptopals.pkcs7_unpad(cracked)
    cracked = cryptopals.base64_decode(str(cracked, encoding='ascii'))
    print(decoded)
    print(cracked)
    assert cracked in decoded
import cryptopals
import random
import pprint

key = cryptopals.get_aes_key()
nonce = random.randbytes(8)

def oracle(attacker_controlled):
    blacklist = [b";", b"="]
    for c in blacklist:
        if c in attacker_controlled:
            raise Exception("invalid character in input")
    pre = b"comment1=cooking%20MCs;userdata="
    post = b";comment2=%20like%20a%20pound%20of%20bacon"
    input = b"".join([pre, attacker_controlled, post])
    print(cryptopals.to_blocks(input, 16))
    print()
    input = cryptopals.pkcs7_padding(input, len(key))
    output = cryptopals.aes_ctr_encrypt(input, key, nonce)
    return output

def isadmin(ciphertext):
    plaintext = cryptopals.aes_ctr_encrypt(ciphertext, key, nonce)
    plaintext = cryptopals.pkcs7_unpad(plaintext)
    print(plaintext)
    print(cryptopals.to_blocks(plaintext, 16))
    d = {}
    for entry in plaintext.split(b";"):
        try:
            k, v = entry.split(b"=")
            d[k] = v
        except: pass
    if not b'admin' in d:
        return False
    return d[b'admin'] == b"true"

def test_solution0():
    enc = oracle(b"this is my userdata")
    assert not isadmin(enc)

def test_solution():
    # CTR: 
    #   ciphertext[i] = keystream[i] ^ plaintext[i]
    # bit flip: 
    #   ciphertext[i] = keystream[i] ^ plaintext[i] ^ plaintext[i] ^ modification[i]
    #   ciphertext[i] = keystream[i] ^ modification[i]
    # 
    encrypted_blocks = cryptopals.to_blocks(oracle(b"a" * 16), 16)
    plaintext_blocks = cryptopals.to_blocks(b"comment1=cooking%20MCs;userdata=" + b"a"*16 + b";comment2=%20like%20a%20pound%20of%20bacon", 16)
    target_block = plaintext_blocks.index(b"a"*16)
    print(encrypted_blocks[target_block])
    print(plaintext_blocks[target_block])
    desired_block = b"a;admin=true;xx="
    assert len(desired_block) == 16
    encrypted_blocks[target_block] = cryptopals.fixed_xor(
        cryptopals.fixed_xor(encrypted_blocks[target_block], plaintext_blocks[target_block]),
        desired_block
    )
    tampered = b"".join(encrypted_blocks)
    print(tampered)
    assert isadmin(tampered)

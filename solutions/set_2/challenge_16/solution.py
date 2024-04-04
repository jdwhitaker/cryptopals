from ..challenge_12.solution import get_random_aes_key
from ..challenge_9.solution import pkcs7_padding
from ..challenge_10.solution import aes_cbc_encrypt
from ..challenge_10.solution import aes_cbc_decrypt
from ..challenge_15.solution import pkcs7_unpad
import random
import pprint

key = get_random_aes_key()
iv = random.randbytes(16)

def oracle(attacker_controlled):
    blacklist = [b";", b"="]
    for c in blacklist:
        if c in attacker_controlled:
            raise Exception("invalid character in input")
    pre = b"comment1=cooking%20MCs;userdata="
    post = b";comment2=%20like%20a%20pound%20of%20bacon"
    input = b"".join([pre, attacker_controlled, post])
    input = pkcs7_padding(input, len(key))
    output = aes_cbc_encrypt(input, key, iv)
    return output

def isadmin(ciphertext):
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)
    plaintext = pkcs7_unpad(plaintext)
    print(plaintext)
    d = {}
    for entry in plaintext.split(b";"):
        print(entry)
        try:
            k, v = entry.split(b"=")
            d[k] = v
        except: pass
    pprint.pprint(d)
    if not b'admin' in d:
        return False
    return d[b'admin'] == b"true"
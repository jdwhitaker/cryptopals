import pytest
import random
import cryptopals
import random
import pprint

key = cryptopals.get_random_aes_key()
iv = random.randbytes(16)

def oracle(attacker_controlled):
    blacklist = [b";", b"="]
    for c in blacklist:
        if c in attacker_controlled:
            raise Exception("invalid character in input")
    pre = b"comment1=cooking%20MCs;userdata="
    post = b";comment2=%20like%20a%20pound%20of%20bacon"
    input = b"".join([pre, attacker_controlled, post])
    input = cryptopals.pkcs7_padding(input, len(key))
    output = cryptopals.aes_cbc_encrypt(input, key, iv)
    return output

def isadmin(ciphertext):
    plaintext = cryptopals.aes_cbc_decrypt(ciphertext, key, iv)
    plaintext = cryptopals.pkcs7_unpad(plaintext)
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

def test_solution0():
    enc = oracle(b"this is my userdata")
    assert not isadmin(enc)

def test_solution():
    # comment1=cooking%20MCs;userdata=aaaaaaaaaaaaaaaaaaaaa;admin=true;comment2=%20like%20a%20pound%20of%20bacon
    # bit flip operations (e.g. XOR) on an encrypted ciphertext block will apply to the subsequent plaintext block
    # because the plaintext block is XOR'd against the prior ciphertext block.
    # They will also scramble the plaintext output of the modified ciphertext block.
    enc = oracle(b"".join([b"aaaaaaaaaaaaaaaaaaaaaxadminxtrue"]))
    patch1_location = len("comment1=cooking%20MCs;userdata=aaaaaaaaaaaaaaaaaaaaa;") - 1 - 16
    patch2_location = len("comment1=cooking%20MCs;userdata=aaaaaaaaaaaaaaaaaaaaa;admin=") - 1 - 16
    enc_copy = b"".join([
        enc[:patch1_location],
        # x & x & ; => ;
        bytes([enc[patch1_location] ^ ord(';') ^ ord('x')]),
        enc[patch1_location+1:patch2_location],
        # x & x & = => =
        bytes([enc[patch2_location] ^ ord('=') ^ ord('x')]),
        enc[patch2_location+1:],
    ])
    assert isadmin(enc_copy)

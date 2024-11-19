import pytest
import random
import cryptopals
import random
import pprint

key = cryptopals.get_aes_key()
#iv = random.randbytes(16)
iv = key

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
    for b in plaintext:
        if b > 127:
            raise Exception("invalid character in input:", plaintext)
    plaintext = cryptopals.pkcs7_unpad(plaintext)
    d = {}
    for entry in plaintext.split(b";"):
        try:
            k, v = entry.split(b"=")
            d[k] = v
        except: pass
    if not b'admin' in d:
        return False
    return d[b'admin'] == b"true"

def test_27():
    # CBC:
    #   C[0] = aes(P[0] ^ iv, k)
    #   C[1] = aes(P[1] ^ C[0], k)
    #   C[2] = aes(P[2] ^ C[1], k)
    # Tampered:
    #   C[0] = aes(P[0] ^ iv, k)
    #   C[1] = 0
    #   C[2] = aes(P[0] ^ iv, k)
    #
    #   P_[0] = P[0] 
    #   P_[1]   = aes_(0, k) ^ C[0]
    #           = aes_(0, k) ^ aes(P[0] ^ iv, k)
    #   P_[2]   = aes_(C[2], k) ^ C[1]
    #           = aes_(C[2], k) ^ 0
    #           = aes_(C[2], k)
    #           = aes_(aes(P[0] ^ iv, k), k)
    #           = P[0] ^ iv
    # Key cracking:
    #   k = P_[0] ^ P_[2] = P[0] ^ P[0] ^ iv = iv = k
    #
    enc = oracle(b"".join([b"aaaaaaaaaaaaaaaaaaaaaxadminxtrue"]))
    enc_blocks = cryptopals.to_blocks(enc, 16)
    print(enc_blocks)
    enc_blocks[1] = bytes([0] * 16)
    enc_blocks[2] = enc_blocks[0]
    enc = b"".join(enc_blocks)
    try:
        print(cryptopals.to_blocks(enc, 16))
        isadmin(enc)
        assert True == False
    except Exception as e:
        pt = e.args[1]
        pt_blocks = cryptopals.to_blocks(pt, 16)
        print(pt_blocks)
        cracked_key = cryptopals.fixed_xor(pt_blocks[0], pt_blocks[2])
        print(cracked_key)
        assert key == cracked_key

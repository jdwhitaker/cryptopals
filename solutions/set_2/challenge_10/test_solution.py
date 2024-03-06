from ..challenge_9.solution import pkcs7_padding
from ...set_1.challenge_7.solution import decrypt_ecb
from .solution import aes_ecb_encrypt, aes_cbc_decrypt, aes_cbc_encrypt
from ...set_1.challenge_6.solution import base64_decode
import os

def test_aes_ecb_encrypt():
    input = b"This is a test"
    key = b"YELLOW SUBMARINE"
    e = aes_ecb_encrypt(pkcs7_padding(input, len(key)), key)
    print('e:', e)
    d = decrypt_ecb(e, key)
    print('d:', d)
    assert d == input

def test_aes_cbc_encrypt():
    input = b"This is a test"
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * len(key)
    e = aes_cbc_encrypt(input, key, iv)
    print('e:', e)
    d = aes_cbc_decrypt(e, key, iv)
    print('d:', d)
    assert d == input

def test_aes_cbc_decrypt2():
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * len(key)
    with open(os.path.join(os.path.dirname(__file__), 'res', '10.txt'), 'r') as f:
        input = f.read()
    input = base64_decode(input)
    output = aes_cbc_decrypt(input, key, iv)
    assert output == b"sound good \n1fragilistiith a spoon!  e. \n\nSteppin' YO! and I can  I was we"
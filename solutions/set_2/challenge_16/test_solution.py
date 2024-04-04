import pytest
from .solution import oracle, isadmin
from ..challenge_10.solution import aes_cbc_encrypt
from ..challenge_10.solution import aes_cbc_decrypt
from ..challenge_12.solution import get_random_aes_key
from ..challenge_9.solution import pkcs7_padding
from ..challenge_15.solution import pkcs7_unpad
import random

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

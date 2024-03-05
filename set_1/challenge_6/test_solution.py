from .solution import break_repeating_key_xor, base64_decode, hamming_distance, get_keylength
from ..challenge_1.solution import bytes_to_base64
from ..challenge_5.solution import encrypt_repeating_key_xor
import os
from base64 import b64decode
import random

def test_hamming_distance():
    input1 = bytes("this is a test", encoding="ascii")
    input2 = bytes("wokka wokka!!!", encoding="ascii")
    distance = hamming_distance(input1, input2)
    assert distance == 37

def test_hamming_distance2():
    input1 = bytes([0b11110000, 0b11110000])
    input2 = bytes([0b11110000, 0b11110000])
    distance = hamming_distance(input1, input2)
    assert distance == 0


def test_hamming_distance3():
    input1 = bytes([0b11110000, 0b11110000])
    input2 = bytes([0b00001111, 0b00001111])
    distance = hamming_distance(input1, input2)
    assert distance == 16

def xtest_base64_decode():
    base_input = "This is a test input"
    for i in range(0, 100):
        input = bytes(base_input + i * chr(i), encoding="ascii")
        print(input)
        enc_input = bytes_to_base64(input)
        assert input == base64_decode(enc_input)

def xtest_keylength():
    with open(os.path.join(os.path.dirname(__file__), 'res', 'test.txt'), 'rb') as f:
        input = f.read()
    k = b"SECRET"
    enc_input = encrypt_repeating_key_xor(input, k)
    key_length = get_keylength(enc_input)
    assert len(k) == key_length

def xtest_break_repeating_key_xor2():
    with open(os.path.join(os.path.dirname(__file__), 'res', 'test.txt'), 'rb') as f:
        input = f.read()
    enc_input = encrypt_repeating_key_xor(input, b"KEY")
    key = break_repeating_key_xor(enc_input)
    decrypted = encrypt_repeating_key_xor(enc_input, key)
    assert decrypted == input

def test_break_repeating_key_xor():
    with open(os.path.join(os.path.dirname(__file__), 'res', '6.txt'), 'r') as f:
        input = f.read()
    input = base64_decode(input)
    key = break_repeating_key_xor(input)
    assert key == b'Terminator X: Bring the noise'
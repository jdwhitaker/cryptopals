import pytest
from .solution import pkcs7_unpad
from ...set_2.challenge_9.solution import pkcs7_padding

def test_solution1():
    input = b"ICE ICE BABY\x04\x04\x04\x04"
    output = pkcs7_unpad(input)
    print(output)
    assert output == b"ICE ICE BABY"

def test_solution2():
    with pytest.raises(Exception):
        input = b"ICE ICE BABY\x05\x05\x05\x05"
        pkcs7_unpad(input)

def test_solution3():
    with pytest.raises(Exception):
        input = b"ICE ICE BABY\x01\x02\x03\x04"
        pkcs7_unpad(input)

def test_solution4():
    input = b"AAAAAAAAAAAAAAA\x01"
    print(input)
    output = pkcs7_padding(input, 16)
    print(output)
    output = pkcs7_unpad(output)
    print(output)
    assert output == input
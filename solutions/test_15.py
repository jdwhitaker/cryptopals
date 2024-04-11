import pytest
import cryptopals

def test_solution1():
    input = b"ICE ICE BABY\x04\x04\x04\x04"
    output = cryptopals.pkcs7_unpad(input)
    print(output)
    assert output == b"ICE ICE BABY"

def test_solution2():
    with pytest.raises(Exception):
        input = b"ICE ICE BABY\x05\x05\x05\x05"
        cryptopals.pkcs7_unpad(input)

def test_solution3():
    with pytest.raises(Exception):
        input = b"ICE ICE BABY\x01\x02\x03\x04"
        cryptopals.pkcs7_unpad(input)

def test_solution4():
    input = b"AAAAAAAAAAAAAAA\x01"
    print(input)
    output = cryptopals.pkcs7_padding(input, 16)
    print(output)
    output = cryptopals.pkcs7_unpad(output)
    print(output)
    assert output == input
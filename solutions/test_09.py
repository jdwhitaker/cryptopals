import cryptopals

def test_pkcs_padding():
    input = b"0123456701234567"
    output = cryptopals.pkcs7_padding(input, 8)
    assert output == b"0123456701234567\x08\x08\x08\x08\x08\x08\x08\x08"

def test_pkcs_padding2():
    input = b"YELLOW SUBMARINE"
    output = cryptopals.pkcs7_padding(input, 4)
    assert output == b"YELLOW SUBMARINE\x04\x04\x04\x04"

def test_pkcs_padding3():
    input = b"AAAAAAAAAAAAAAA\x01"
    output = cryptopals.pkcs7_padding(input, 16)
    assert output == (input + b"\x10" * 16)
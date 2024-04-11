from cryptopals import hex_to_base64, bytes_to_base64
import base64

def test():
    input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    output = hex_to_base64(input)
    assert output == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

def test_1():
    input = bytes("I'm killing your brain like a poisonous mushroom", encoding="ASCII")
    output = bytes_to_base64(input)
    assert base64.b64decode(output) == b"I'm killing your brain like a poisonous mushroom"

def test_2():
    prefix = "This is another input! "
    inputs = [
        prefix,
        prefix + "1",
        prefix + "12",
        prefix + "123",
        prefix + "1234",
        prefix + "12345",
    ]
    for input in inputs:
        input = bytes(input, encoding="ASCII")
        output = bytes_to_base64(input)
        assert base64.b64decode(output) == input
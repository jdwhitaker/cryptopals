from . import solution
from ..challenge_1.solution import hex_to_bytes

def test_1():
    input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    input = hex_to_bytes(input)
    output = solution.crack_single_xor_cipher(input)
    print(output)
    assert output == b"Cooking MC's like a pound of bacon"
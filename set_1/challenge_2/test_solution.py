from . import solution
from ..challenge_1.solution import hex_to_bytes

def test_1():
    input1 = "1c0111001f010100061a024b53535009181c"
    input2 = "686974207468652062756c6c277320657965"
    bytes1 = hex_to_bytes(input1)
    print(bytes1)
    bytes2 = hex_to_bytes(input2)
    print(bytes2)
    output = solution.fixed_xor(bytes1, bytes2)
    print(output)
    output = solution.bytes_to_hex(output)
    print(output)
    assert output == "746865206b696420646f6e277420706c6179"
from ..challenge_1.solution import hex_to_bytes
from .solution import encrypt_repeating_key_xor

def test_1():
    input = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
    input = bytes(input, encoding='ASCII')
    output = encrypt_repeating_key_xor(input, bytes("ICE", encoding='ASCII'))
    print(output)
    correct_output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    correct_output = hex_to_bytes(correct_output)
    print(output)
    print(correct_output)
    assert output == correct_output
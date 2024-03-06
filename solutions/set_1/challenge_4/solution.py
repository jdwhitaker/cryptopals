from ..challenge_3.solution import crack_single_xor_cipher
from ..challenge_3.solution import decryption_metric
from ..challenge_1.solution import hex_to_bytes
from ..challenge_2.solution import fixed_xor

def detect_single_character_xor():
    with open('./solutions/set_1/challenge_4/4.txt', 'r') as f:
        inputs = f.read().split('\n')
    outputs = []
    for input in inputs:
        bytes = hex_to_bytes(input)
        key = crack_single_xor_cipher(bytes)
        cracked = fixed_xor(bytes, key)
        metric = decryption_metric(cracked)
        outputs.append((metric, cracked))
    outputs = [i for i in sorted(outputs, key = lambda j: j[0])]
    return outputs[-1][1]
from cryptopals import detect_single_character_xor

def test_1():
    with open('./res/4.txt', 'r') as f:
        inputs = f.read().split('\n')
    output = detect_single_character_xor(inputs)
    assert output == b'Now that the party is jumping\n'
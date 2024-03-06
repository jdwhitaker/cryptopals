from ..challenge_2.solution import fixed_xor
import string

def decryption_metric(bs):
    frequencies = {
        'a': 5.35788,
        'b': 0.9801,
        'c': 1.8295199999999998,
        'd': 2.80962,
        'e': 8.298179999999999,
        'f': 1.43748,
        'g': 1.3068,
        'h': 3.98574,
        'i': 4.5738,
        'j': 0.09801,
        'k': 0.503118,
        'l': 2.6136,
        'm': 1.56816,
        'n': 4.37778,
        'o': 4.9005,
        'p': 1.24146,
        'q': 0.062072999999999996,
        'r': 3.9204,
        's': 4.11642,
        't': 5.945939999999999,
        'u': 1.8295199999999998,
        'v': 0.640332,
        'w': 1.56816,
        'x': 0.09801,
        'y': 1.3068,
        'z': 0.048351599999999995,
        ' ': 20,
        '.': 6.5,
        '"': 2.7,
        "'": 2.4,
        "-": 1.5,
        "?": .56,
        ":": .34,
        "!": .33,
        ";": .33,
        "\n": 0,
        "\t": 0,
    }
    original = bs
    bs = bs.lower().decode('ascii', errors='ignore')
    #if bs.count(' ') < 1: return -100
    #bs = ''.join([i for i in bs if i.isalpha() or i in " '"])
    #if len(bs) / len(original) < .9: return -100
    observed_frequencies = {
        i: bs.count(i) / len(original) for i in frequencies.keys()
    }
    mse = 0
    for key in observed_frequencies.keys():
        mse += (observed_frequencies.get(key, 0) - frequencies.get(key, 0)) ** 2
    mse /= len(observed_frequencies.keys())
    return -1 * mse 

def crack_single_xor_cipher(bs):
    outputs = []
    for k in range(0,256):
        key = bytes([k for i in range(len(bs))])
        decrypted = fixed_xor(bs, key)
        metric = decryption_metric(decrypted)
        outputs.append((bytes([k]), metric, decrypted))
    outputs = sorted(outputs, key = lambda i: -i[1])
    #for i in outputs[:5]: print(i)
    return outputs[0][0]
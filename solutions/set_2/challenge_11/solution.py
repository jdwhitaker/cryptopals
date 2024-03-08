import random
from ..challenge_9.solution import pkcs7_padding
from ..challenge_10.solution import aes_cbc_encrypt
from ..challenge_10.solution import aes_ecb_encrypt
from ...set_1.challenge_6.solution import mean_hamming_score, to_blocks

random.seed(0)

def generate_random_aes_key():
    return random.randbytes(16)

def encryption_oracle(input):
    print('encryption_oracle')
    random_before = random.randbytes(random.randint(5,10))
    random_post = random.randbytes(random.randint(5,10))
    input = random_before + input + random_post
    input = pkcs7_padding(input, 16)
    key = generate_random_aes_key()
    algo = random.randint(0,1)
    if algo == 0:
        output = aes_ecb_encrypt(input, key)
        return (output, 'ecb')
    else:
        iv = generate_random_aes_key()
        output = aes_cbc_encrypt(input, key, iv)
        return (output, 'cbc')

def classify_ecb_cbc(input):
    freqdist = {}
    blocks = to_blocks(input, 16)
    for b in blocks:
        if not b in freqdist:
            freqdist[b] = 0
        freqdist[b] += 1
    print(freqdist)
    metric = sum([v for k,v in freqdist.items()]) / len(freqdist)
    print(metric)
    if metric > 1.001:
        return 'ecb'
    else:
        return 'cbc'
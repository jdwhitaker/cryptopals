import random
from ..challenge_10.solution import aes_ecb_encrypt
from ..challenge_12.solution import get_random_aes_key
from ..challenge_9.solution import pkcs7_padding

random.seed(0)

TARGET_BYTES = b"these are the target bytes"
RANDOM_PREFIX = random.randbytes(random.randint(100,200))

def oracle(attacker_controlled):
    random_key = get_random_aes_key()
    input = b"".join([RANDOM_PREFIX, attacker_controlled, TARGET_BYTES])
    input = pkcs7_padding(input, 16)
    return aes_ecb_encrypt(input, random_key)

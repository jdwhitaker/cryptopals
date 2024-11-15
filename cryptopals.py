import string
import math
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import random
import struct
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

random.seed(0)

def frequency_distribution(items):
    fd = {}
    for item in items:
        if not item in fd:
            fd[item] = 0
        fd[item] += 1
    return fd

def vectorize(bs):
    X = [0 for _ in range(256)]
    fd = frequency_distribution(bs)
    for k, v in fd.items():
        X[k] = v / len(bs)
    return np.array(X).reshape(1, -1)

with open('./res/6_test.txt', 'rb') as f:
    vectorized_plaintext_corpus = vectorize(f.read())

def bytes_to_base64(bytes):
    value = int.from_bytes(bytes, byteorder="big")
    output = []
    n_bits = len(bytes) * 8
    i_bit = 0
    while i_bit < n_bits:
        offset = n_bits - i_bit - 6
        if offset > -1:
            mask = 0b111111 << offset
        else:
            mask = 0b111111 >> abs(offset )
        segment = value & mask
        if offset > -1:
            segment = segment >> offset
        else:
            segment = segment << abs(offset)
        if segment < 26: # A-Z
            c = chr(ord("A") + segment)
        elif segment < 52: # a-z
            c = chr(ord("a") + segment - 26)
        elif segment < 62: # 0-9
            c = chr(ord("0") + segment - 52)
        elif segment < 63: # +
            c = "+"
        else: # /
            c = "/"
        output.append(c)
        i_bit += 6
    while len(output) % 4 != 0:
        output.append('=')
    return ''.join(output)

def hex_to_bytes(hex):
    def hexchar_to_int(hexchar):
        if ord(hexchar) >= ord('a'):
            return 10 + ord(hexchar) - ord('a')
        else:
            return ord(hexchar) - ord('0')

    lst = []
    i = 0
    while i < (len(hex) - 1):
        n1 = hexchar_to_int(hex[i])
        n0 = hexchar_to_int(hex[i+1])
        lst.append(n1 * 16 + n0)
        i += 2
    return bytes(lst)

def hex_to_base64(hex):
    return bytes_to_base64(hex_to_bytes(hex))

def fixed_xor(bytes1, bytes2):
    if len(bytes2) == 1:
        bytes2 = bytes2 * len(bytes1)
    output = []
    for b1, b2 in zip(bytes1, bytes2):
        o = b1 ^ b2
        output.append(o)
    return bytes(output)

def bytes_to_hex(bytes):
    def nibble_to_hex(nibble):
        if nibble < 10:
            return chr(ord('0') + nibble)
        else:
            return chr(ord('a') + nibble - 10)

    output = []
    for b in bytes:
        upper = (b & 0b11110000) >> 4
        lower = b & 0b00001111
        upper = nibble_to_hex(upper)
        lower = nibble_to_hex(lower)
        output.append(upper)
        output.append(lower)
    return ''.join(output)

def crack_single_xor_cipher(bs):
    outputs = []
    for k in range(0,256):
        key = bytes([k for i in range(len(bs))])
        decrypted = fixed_xor(bs, key)
        metric = decryption_metric(vectorized_plaintext_corpus, vectorize(decrypted))
        outputs.append((bytes([k]), metric, decrypted))
    outputs = sorted(outputs, key = lambda i: -i[1])
    #for i in outputs[:5]: print(i)
    return outputs[0][0]

def detect_single_character_xor(inputs):
    outputs = []
    for input in inputs:
        bytes = hex_to_bytes(input)
        key = crack_single_xor_cipher(bytes)
        cracked = fixed_xor(bytes, key)
        metric = decryption_metric(vectorized_plaintext_corpus, vectorize(cracked))
        outputs.append((metric, cracked))
    outputs = [i for i in sorted(outputs, key = lambda j: j[0])]
    return outputs[-1][1]

def encrypt_repeating_key_xor(input, key):
    output = []
    for i in range(len(input)):
        o = input[i] ^ key[i % len(key)]
        output.append(o)
    return bytes(output)

def base64_decode(input):
    input = input.replace('\n', '')
    output = []
    for i, c in enumerate(input):
        #print(i, c)
        value = None
        c = ord(c)
        if c >= ord('A') and c <= ord('Z'):
            value = c - ord('A')
        elif c >= ord('a') and c <= ord('z'):
            value = 26 + c - ord('a')
        elif c >= ord('0') and c <= ord('9'):
            value = 52 + c - ord('0')
        elif chr(c) == "+":
            value = 62
        elif chr(c) == "/":
            value = 63
        elif chr(c) == "=":
            if output[-1] == 0:
                output = output[:-1]
            break
        else:
            raise Exception("Invalid input " + chr(c))
        #print("{:06b}".format(value))
        if i % 4 == 0:
            #print('block 0')
            value = value << 2
            # 12345600
            output.append(value)
        elif i % 4 == 1:
            #print('block 1')
            output[-1] = output[-1] | (value >> 4)
            # 12345612
            value = ((value << 4) & 0xFF)
            output.append(value)
            # 34560000
        elif i % 4 == 2:
            #print('block 2')
            output[-1] = output[-1] | (value >> 2)
            # 34561234
            value = ((value << 6) & 0xFF)
            output.append(value)
            # 56000000
        else:
            #print('block 3')
            output[-1] = output[-1] | value
            # 56123456
        #print(["{:08b}".format(i) for i in output])
        #print()
    return bytes(output)

def hamming_distance(input1, input2):
    distance = 0
    for i1, i2 in zip(input1, input2):
        for i in range(8):
            x = i1 >> i
            y = i2 >> i
            if (x & 0b1) != (y & 0b1):
                distance += 1
    return distance

def mean_hamming_score(input, blocksize):
    total = 0
    n = 0
    blocks = to_blocks(input, blocksize)
    for i in range(len(blocks) - 1):
        if n > 1_000_000: # sample size ~1,000,000
            break
        for j in range(i+1, len(blocks)):
            metric = hamming_distance(blocks[i], blocks[j]) 
            n += 1
            total += metric
    metric = (total / n) / blocksize
    return metric

def get_keylength(input):
    keylengths = []
    for keylength in range(2, 41):
        metric = mean_hamming_score(input, keylength)
        keylengths.append((keylength, metric))
        print((keylength, metric))
    keylengths = sorted(keylengths, key = lambda i: i[1])
    possibilities = [i for i in keylengths if i[1] < 2.72]
    if len(possibilities) == 0:
        return keylengths[0][0]
    smallest_possibility = min([i[0] for i in possibilities])
    return smallest_possibility

def transpose(blocks):
    n = len(blocks[0])
    output = [[] for _ in range(n)]
    for block in blocks:
        for i, b in enumerate(block):
            output[i % n].append(b)
    output = [bytes(i) for i in output]
    return output

def flatten(lst):
    output = []
    for l in lst:
        for i in l:
            output.append(i)
    return bytes(output)

def break_repeating_key_xor(input):
    keylength = get_keylength(input)
    blocks = to_blocks(input, keylength)
    transposed = transpose(blocks)
    key = []
    for i in range(len(transposed)):
        t = transposed[i]
        key.append(crack_single_xor_cipher(t))
    key = b"".join(key)
    return key


def to_blocks(input, block_length):
    n_blocks = math.ceil(len(input) / block_length)
    input = input + bytes([0 for i in range((len(input) - n_blocks * block_length))])
    blocks = []
    for i in range(n_blocks):
        block = input[i*block_length:(i+1)*block_length]
        blocks.append(block)
    return blocks
    
def decrypt_ecb(ciphertext, key):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.ECB()
    ).decryptor()
    output = decryptor.update(ciphertext) + decryptor.finalize()
    return output

def pkcs7_unpad(input):
    n = input[-1]
    if n == 0:
        raise Exception("Invalid padding")
    for i in range(n):
        if input[-(i+1)] != n:
            raise Exception("Invalid padding")
    return input[:-n]

def detect_ecb(inputs):
    scores = [0 for _ in range(len(inputs))]
    for idx, input in enumerate(inputs):
        scores[idx] = mean_hamming_score(input, 16)
    scores_inputs = sorted(zip(scores, inputs), key = lambda i: i[0])
    for score, input in scores_inputs:
        print(score)
        print(input)
        print()
    return scores_inputs

def pkcs7_padding(input, blocklength):
    n = blocklength - (len(input) % blocklength)
    pad = bytes([n for _ in range(n)])
    output = input + pad
    return output

def aes_ecb_encrypt(input, key):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.ECB()
    ).encryptor()
    output = encryptor.update(input) + encryptor.finalize()
    return output

def aes_cbc_decrypt(ciphertext, key, iv):
    blocks = to_blocks(ciphertext, len(key))
    output = []
    prior_ciphertext = iv
    for block in blocks:
        plaintext = decrypt_ecb(block, key)
        assert len(plaintext) == len(prior_ciphertext)
        plaintext = bytes([a ^ b for a, b in zip(plaintext, prior_ciphertext)])
        prior_ciphertext = block
        output.append(plaintext)
    return b"".join(output)

def aes_cbc_encrypt(input, key, iv):
    blocks = to_blocks(input, len(key))
    output = []
    prior_ciphertext = iv
    for block in blocks:
        assert len(block) == len(prior_ciphertext)
        block = bytes([a ^ b for a, b in zip(block, prior_ciphertext)])
        ciphertext = aes_ecb_encrypt(block, key)
        prior_ciphertext = ciphertext
        output.append(ciphertext)
    return b"".join(output)

def get_aes_key():
    return random.randbytes(16)

def classify_ecb_cbc(input):
    freqdist = {}
    blocks = to_blocks(input, 16)
    for b in blocks:
        if not b in freqdist:
            freqdist[b] = 0
        freqdist[b] += 1
    metric = sum([v for k,v in freqdist.items()]) / len(freqdist)
    if metric > 1.001:
        return 'ecb'
    else:
        return 'cbc'

def aes_ctr_keystream(key, nonce, length):
    keystream = []
    ctr = 0
    while (len(keystream) * 16) < length:
        input = b"".join([nonce, struct.pack("<Q", ctr)])
        assert len(input) == 16
        k = aes_ecb_encrypt(input, key)
        keystream.append(k)
        ctr += 1
    keystream = b"".join(keystream)
    keystream = keystream[:length]
    return keystream

def aes_ctr_encrypt(input, key, nonce):
    keystream = aes_ctr_keystream(key, nonce, len(input))
    output = fixed_xor(input, keystream)
    return output

def decryption_metric(vectorized_plaintext_corpus, vectorized_possible_plaintext):
    return cosine_similarity(vectorized_plaintext_corpus, vectorized_possible_plaintext)[0][0]

class MersenneTwisterRNG:
    n = 624
    m = 397
    w = 32
    r = 31
    f = 1812433253
    u = 11
    s = 7
    t = 15
    l = 18
    a = 0x9908b0df
    b = 0x9d2c5680
    c = 0xefc60000
    UMASK = (0xffffffff << r) % (2**w)
    LMASK = (0xffffffff >> (w-r))
    state = [0 for _ in range(n)]
    i = 0

    def __init__(self, seed):
        self.state[0] = seed
        for i in range(1, self.n):
            x_prior = self.state[i-1]
            self.state[i]  = (self.f * (x_prior ^ (x_prior >> (self.w-2))) + i) % (2**self.w)

    def random(self):
        k = self.i
        j = (k - (self.n - 1)) % self.n
        x = (self.state[k] & self.UMASK) | (self.state[j] & self.LMASK)
        xA = x >> 1
        if (x & 0x00000001): xA ^= self.a;
        j = (k - (self.n-self.m)) % self.n
        x = self.state[j] ^ xA;
        self.state[k] = x
        k = (k + 1) % self.n
        self.i = k
        y = x ^ (x >> self.u)
        y = y ^ (((y << self.s) % (2**self.w)) & self.b)
        y = y ^ (((y << self.t) % (2**self.w)) & self.c)
        z = y ^ (y >> self.l)
        return z % (2**self.w)
from ..challenge_3.solution import crack_single_xor_cipher
from ..challenge_3.solution import decryption_metric
from ..challenge_5.solution import encrypt_repeating_key_xor
import math

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
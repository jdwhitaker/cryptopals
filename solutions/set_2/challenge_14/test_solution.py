import pytest
from .solution import oracle
from ...set_1.challenge_6.solution import to_blocks
import pprint

padding_length = None

def get_padding_length():
    global padding_length
    if padding_length == None:
        maximum_length = 0 
        max_delimeter_count = 0
        # create a padding sequence of identical blocks in the middle of the ciphertext.
        # to ensure the target blocks start on a ciphertext block boundary,
        # decrease our padding length until we know we hit a block boundary
        # by the number of identical delimeter blocks decreasing
        for i in range(16 * 5, 0, -1):
            input = b"A" * i
            output = oracle(input)
            output = to_blocks(output, 16)
            maximum_length = max(maximum_length, len(output))
            #print(output)
            counts = {}
            for block in output:
                if not block in counts:
                    counts[block] = 0
                counts[block] += 1
            #pprint.pprint(counts)
            delimeter_count = sorted(counts.items(), key = lambda i: -i[1])[0][1]
            max_delimeter_count = max(max_delimeter_count, delimeter_count)
            if delimeter_count < max_delimeter_count:
                return i+1
            #print(delimeter)
            #print(len(output))
    else:
        return padding_length

def target_bytes_oracle(attacker_controlled):
    # the target bytes are after a bunch of identical padding blocks in the middle
    padding_length = get_padding_length()
    #print("padding_length:", padding_length)
    input = (b"A" * padding_length) + attacker_controlled
    output = oracle(input)
    #print("input:", input)
    #print("output:", output)
    output = to_blocks(output, 16)
    counts = {}
    for block in output:
        if not block in counts:
            counts[block] = 0
        counts[block] += 1
    delimeter = sorted(counts.items(), key = lambda i: -i[1])[0][0]
    #print("delimeter:", delimeter)
    target_blocks = []
    begin = False
    for block in output:
        if block == delimeter:
            begin = True
        if begin and block != delimeter:
            target_blocks.append(block)
    target_bytes = b"".join(target_blocks)
    #print("target_bytes:", target_bytes)
    return target_bytes

def crack_ecb():
    # we can now parse out the target bytes. 
    # we control the prefix of these target bytes, so we can use a static prefix of 15 bytes to brute force
    # the first byte. Then, we can brute force subsequent bytes using a static prefix and the cracked bytes
    block_length = 16
    cracked = []
    offset = 0
    while True:
        iblock = offset // block_length
        ibyte = offset % block_length
        print(iblock, ibyte)
        lookup = {}
        prefix = b"B"*(block_length-ibyte-1)
        for i in range(256):
            value = prefix + bytes(cracked) + bytes([i])
            key = target_bytes_oracle(value)[block_length*iblock:block_length*(iblock+1)]
            print(key, value)
            lookup[key] = value
        #print("prefix:", prefix)
        ciphertext = target_bytes_oracle(prefix)
        output = ciphertext[block_length*iblock:block_length*(iblock+1)]
        #print("lookup:")
        #pprint.pprint(lookup)
        #print(f"output ({len(output)}): {output}")
        if not output in lookup:
            return bytes(cracked)[:-cracked[-1]]
        c = lookup[output][-1]
        #print("cracked byte:", c)
        cracked.append(c)
        #print("cracked:", bytes(cracked))
        #print()
        offset += 1
        #print(offset, len(ciphertext))

def test_solution():
    cracked = crack_ecb()
    print(cracked)
    assert cracked == b"these are the target bytes"
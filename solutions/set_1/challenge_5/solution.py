def encrypt_repeating_key_xor(input, key):
    output = []
    for i in range(len(input)):
        o = input[i] ^ key[i % len(key)]
        output.append(o)
    return bytes(output)
def fixed_xor(bytes1, bytes2):
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

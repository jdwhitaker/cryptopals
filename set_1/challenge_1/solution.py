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


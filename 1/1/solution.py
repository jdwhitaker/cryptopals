def bytes_to_base64(bytes):
    value = int.from_bytes(bytes, byteorder="big")
    output = []
    while value > 0:
        segment = value & 0b111111
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
        value = value >> 6
    output = output[::-1]
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

input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
print(hex_to_bytes(input))
print(hex_to_base64(input))
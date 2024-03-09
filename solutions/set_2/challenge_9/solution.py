def pkcs7_padding(input, blocklength):
    n = blocklength - (len(input) % blocklength)
    pad = bytes([n for _ in range(n)])
    output = input + pad
    return output
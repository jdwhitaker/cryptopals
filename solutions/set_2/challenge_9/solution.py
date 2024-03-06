def pkcs7_padding(input, blocklength):
    n = blocklength - (len(input) % blocklength)
    print(n)
    print(input)
    pad = bytes([n for _ in range(n)])
    print(pad)
    output = input + pad
    print(output)
    return output
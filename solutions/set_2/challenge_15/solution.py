def pkcs7_unpad(input):
    n = input[-1]
    for i in range(n):
        if input[-(i+1)] != n:
            raise Exception("Invalid padding")
    return input[:-n]
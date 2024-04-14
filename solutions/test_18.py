import cryptopals


test_string = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

key = b"YELLOW SUBMARINE"
nonce = bytes([0 for _ in range(8)])

def test_18():
    input = cryptopals.base64_decode(test_string)
    output = cryptopals.aes_ctr_encrypt(input, key, nonce)
    print(output)
    assert output == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
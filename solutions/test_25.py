import cryptopals

cached_keystream = None

def edit(ciphertext, key, nonce, offset, newtext):
    global cached_keystream
    if cached_keystream == None:
        cached_keystream = cryptopals.aes_ctr_keystream(key, nonce, len(ciphertext))
    new_ciphertext = cryptopals.fixed_xor(cached_keystream[offset:offset+len(newtext)], newtext)
    out = [ciphertext[i] for i in range(len(ciphertext))]
    for i in range(len(new_ciphertext)):
        out[offset+i] = new_ciphertext[i]
    return bytes(out)

def test_25():
    key = cryptopals.get_aes_key()
    nonce = bytes([0]*8)
    with open('res/25.txt', 'r') as f:
        plaintext = f.read()
    plaintext = cryptopals.base64_decode(plaintext)
    ciphertext = cryptopals.aes_ctr_encrypt(plaintext, key, nonce)
    # crack by guess & check
    cracked = []
    for i in range(len(ciphertext)):
        for j in range(256):
            edited_ciphertext = edit(ciphertext, key, nonce, i, bytes([j]))
            if edited_ciphertext[i] == ciphertext[i]:
                cracked.append(j)
    cracked = bytes(cracked)
    print(plaintext)
    print(cracked)
    assert cracked == plaintext
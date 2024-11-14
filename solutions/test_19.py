import cryptopals

def test_19():
    random_aes_key = cryptopals.get_aes_key()
    null_nonce = bytes([0 for _ in range(8)])
    with open('./res/19.txt', 'r') as f:
        plaintexts = [cryptopals.base64_decode(i) for i in f.read().split('\n')]
    vectorized_plaintext_corpus = cryptopals.vectorize(b''.join(plaintexts))
    ciphertexts = [cryptopals.aes_ctr_encrypt(i, random_aes_key, null_nonce) for i in plaintexts]
    ciphertexts = sorted(ciphertexts, key = lambda i: -len(i))
    keystream = []
    # for each index of each ciphertext
    for i in range(len(ciphertexts[0])):
        key_performance = []
        for key in range(256):
            eligible_ciphertexts = [c for c in ciphertexts if len(c) > i]
            # get a guess of what the characters at this index are
            crack_guesses = bytes([key ^ ciphertext[i] for ciphertext in eligible_ciphertexts])
            # do statistical analysis of the guesses to see which guess is right
            performance = cryptopals.decryption_metric(vectorized_plaintext_corpus, cryptopals.vectorize(crack_guesses))
            key_performance.append((key, performance))
        key_performance.sort(key = lambda i: -i[1])
        keystream.append(key_performance[0][0])
        print(keystream)
    cracked = [cryptopals.fixed_xor(ct, keystream).lower() for ct in ciphertexts]
    assert b'a terrible beauty is born.' in [p.lower() for p in plaintexts]
    assert b'a terrible beauty is born.' in cracked
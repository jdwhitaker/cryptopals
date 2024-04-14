from cryptopals import classify_ecb_cbc, pkcs7_padding, aes_ecb_encrypt, get_aes_key, aes_cbc_encrypt
import random

def encryption_oracle(input):
    random_before = random.randbytes(random.randint(5,10))
    random_post = random.randbytes(random.randint(5,10))
    input = random_before + input + random_post
    input = pkcs7_padding(input, 16)
    key = get_aes_key()
    algo = random.randint(0,1)
    if algo == 0:
        output = aes_ecb_encrypt(input, key)
        return (output, 'ecb')
    else:
        iv = get_aes_key()
        output = aes_cbc_encrypt(input, key, iv)
        return (output, 'cbc')


def test_solution():
    with open('res/11.txt', 'rb') as f:
        english = f.read()
    data_label = [encryption_oracle(english) for _ in range(20)]
    for data, label in data_label:
        print(label, data[:10])
    classifications = [classify_ecb_cbc(data) for data, _ in data_label]
    print(classifications)
    for (data, label), classification in zip(data_label, classifications):
        print("classification:", classification)
        print("label:", label)
        print()
        assert label == classification
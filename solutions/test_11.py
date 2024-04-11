from cryptopals import classify_ecb_cbc, encryption_oracle

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
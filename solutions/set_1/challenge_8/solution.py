from ..challenge_6.solution import mean_hamming_score

def detect_ecb(inputs):
    scores = [0 for _ in range(len(inputs))]
    for idx, input in enumerate(inputs):
        scores[idx] = mean_hamming_score(input, 16)
    scores_inputs = sorted(zip(scores, inputs), key = lambda i: i[0])
    for score, input in scores_inputs:
        print(score)
        print(input)
        print()
    return scores_inputs
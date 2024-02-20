from ..challenge_2.solution import fixed_xor

def decryption_metric(bs):
    def is_alpha(b):
        return (
            (b >= ord('A') and b <= ord('Z')) or 
            (b >= ord('a') and b <= ord('z'))
        )

    alphanum = [b for b in bs if is_alpha(b)]
    return len(alphanum) / len(bs)

def crack_single_xor_cipher(bs):
    winner_metric = 0
    winner_value = None
    for k in range(0,256):
        key = bytes([k for i in range(len(bs))])
        decrypted = fixed_xor(bs, key)
        metric = decryption_metric(decrypted)
        print(k, metric, decrypted)
        if metric > winner_metric:
            winner_metric = metric
            winner_value = decrypted
    return winner_value
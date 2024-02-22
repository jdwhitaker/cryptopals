from ..challenge_2.solution import fixed_xor

def decryption_metric(bs):
    def is_normal(b):
        return (
            (b >= ord('a') and b <= ord('z'))
        )

    def is_weird(b):
        return (
            (b < 32) or 
            (b >= 123)
        )

    normal = len([b for b in bs if is_normal(b)])
    weird = len([b for b in bs if is_weird(b)])
    return (normal / len(bs)) - (weird / len(bs))

def crack_single_xor_cipher(bs):
    winner_metric = 0
    winner_value = None
    for k in range(0,256):
        key = bytes([k for i in range(len(bs))])
        decrypted = fixed_xor(bs, key)
        metric = decryption_metric(decrypted)
        if winner_value == None or metric > winner_metric:
            winner_metric = metric
            winner_value = decrypted
    return winner_value
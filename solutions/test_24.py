import cryptopals
import random
import datetime

def test_24():
    power = 12 # to speed testing up
    # generate 16 bit seed
    seed = random.randint(0, 2**power)
    print('seed: ', seed)
    prefix = random.randbytes(random.randint(10, 100))
    plaintext = prefix + b'A' * 14
    ct = cryptopals.mt19937_ctr_encrypt(seed, plaintext)
    # guess key
    rng = cryptopals.MersenneTwisterRNG(10)
    key_sequence = []
    for i in range(14):
        ct_ = ct[-(i+1)]
        xor = ct_ ^ ord('A')
        key_sequence.append(xor)
    key_sequence = key_sequence[::-1]
    # find seeds which produce the key sequence
    cracked_seed = 0
    for i in range(2**power):
        rng = cryptopals.MersenneTwisterRNG(i)
        keys = []
        for _ in range(624):
            keys.append(rng.random() % 2**8)
        presence = [k in keys for k in key_sequence]
        if not all(presence):
            continue
        k_i = keys.index(key_sequence[0])
        fail = False
        for k in key_sequence:
            if not (keys[k_i] == k):
                fail = True
                break
            k_i += 1
            k_i = k_i % 624
        if not fail:
            cracked_seed = i
            break
            print('cracked seed:', i)

    assert seed == cracked_seed

    #Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.
    ts_now = int(datetime.datetime.now().timestamp())
    rng = cryptopals.MersenneTwisterRNG(ts_now)
    pw_reset_token = rng.random()
    print(pw_reset_token)
    state = cryptopals.untemper(pw_reset_token)
    print(state)
    evil_rng = cryptopals.MersenneTwisterRNG(ts_now)
    evil_rng.random()
    is_pw_reset_token = state in evil_rng.state
    assert is_pw_reset_token == True
    not_a_pw_reset_token = pw_reset_token + 1
    state = cryptopals.untemper(not_a_pw_reset_token)
    is_pw_reset_token = state in evil_rng.state
    assert is_pw_reset_token == False

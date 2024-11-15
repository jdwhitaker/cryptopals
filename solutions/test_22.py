import cryptopals
import datetime
import random
import time

start_time = int(datetime.datetime.now().timestamp())
current_time = start_time

def get_timestamp():
    # use MS instead of seconds to make it run faster but still be real 
    return int(1_000 * round(datetime.datetime.now().timestamp(), 3)) % 2**32

def random_wait():
    global current_time
    offset = random.randint(40,1000)
    time.sleep(offset / 1_000)


def test_22():
    random_wait()
    seed = get_timestamp()
    print('seed: ', seed)
    rng = cryptopals.MersenneTwisterRNG(seed)
    random_wait()
    random_value = rng.random()
    # crack it 
    crack_seed = None
    now = get_timestamp()
    for i in range(now, now - 2000, -1):
        print(i)
        crack_rng = cryptopals.MersenneTwisterRNG(i)
        crack_output = crack_rng.random()
        if crack_output == random_value:
            print('cracked:', i)
            crack_seed = i
            break
    assert crack_seed == seed
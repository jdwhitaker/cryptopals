import cryptopals
import random

n = 624
m = 397
w = 32
r = 31
f = 1812433253
u = 11
s = 7
t = 15
l = 18
a = 0x9908b0df
b = 0x9d2c5680
c = 0xefc60000

def shiftl(value, shift, width):
    return (value << shift) % (2**width)

def shiftl_and_mask(value, shift_width, and_mask):
    print(f'{and_mask:0>32b} <- mask')
    xor = shiftl(value,shift_width,w) & and_mask
    value = value ^ xor
    return value

def shiftr(value, shift_width):
    shifted = value >> shift_width
    value = value ^ shifted
    return value

def temper(x):
    y = x ^ (x >> u)
    y = y ^ (((y << s) % (2**w)) & b)
    y = y ^ (((y << t) % (2**w)) & c)
    z = y ^ (y >> l)
    return z % (2**w)


def test_23():
    for i in range(100):
        x = random.randint(0,2**32-1)
        x_t = temper(x)
        x_ = cryptopals.untemper(x_t)
        assert x == x_
    rng = cryptopals.MersenneTwisterRNG(1234)
    state = [cryptopals.untemper(rng.random()) for _ in range(624)]
    for s in state:
        print(s, rng.state.index(s))
    dupe_rng = cryptopals.MersenneTwisterRNG(0)
    dupe_rng.state = state
    for i in range(10):
        r1 = rng.random()
        r2 = dupe_rng.random()
        assert r1 == r2
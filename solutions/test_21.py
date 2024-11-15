import cryptopals

def test_21():
    rng = cryptopals.MersenneTwisterRNG(1234)
    r = rng.random()
    assert r == 822569775 # from https://leventozturk.com/engineering/random/
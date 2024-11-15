import cryptopals

def test_21():
    rng = cryptopals.MersenneTwisterRNG(1234)
    assert rng.random() == 822569775 # from https://leventozturk.com/engineering/random/
    assert rng.random() == 2137449171
    assert rng.random() == 2671936806
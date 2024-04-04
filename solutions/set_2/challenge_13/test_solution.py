import pytest
from .solution import parse_kv, profile_for, encrypt_profile, decrypt_profile
from ...set_1.challenge_6.solution import to_blocks
from ...set_2.challenge_9.solution import pkcs7_padding
from ...set_2.challenge_15.solution import pkcs7_unpad

def test_parse_kv():
    input = 'foo=bar&baz=qux&zap=zazzle'
    output = parse_kv(input)
    correct = {
        'foo': 'bar', 
        'baz': 'qux', 
        'zap': 'zazzle'
    }
    print(output)
    assert output == correct

def test_parse_kv_negative1():
    with pytest.raises(Exception):
        input = 'foo=b=ar&baz=qux&zap=zazzle'
        output = parse_kv(input)
        print(output)

def test_parse_kv_negative2():
    with pytest.raises(Exception):
        input = 'foo=bar&baz=qux&&zap=zazzle'
        output = parse_kv(input)
        print(output)

def test_profile_for():
    input = "foo@bar.com"
    output = profile_for(input)
    correct = 'email=foo@bar.com&uid=10&role=user'
    assert output == correct

def test_profile_for_negative1():
    with pytest.raises(Exception):
        profile_for("foo@bar.com&")

def test_profile_for_negative2():
    with pytest.raises(Exception):
        profile_for("foo@bar.com=")

def test_solution1():
    print('encrypting profile')
    enc_profile = encrypt_profile('foo@bar.com')
    print('decrypting profile')
    profile = decrypt_profile(enc_profile)
    assert profile['email'] == 'foo@bar.com'
    assert profile['role'] == 'user'
    assert profile['uid'] == '10'

def test_solution2():
    # email=a@aaaaaaa. com&uid=10&role= admin
    ct1 = encrypt_profile('a@aaaaaaa.com')
    ct1 = to_blocks(ct1, 16)
    # email=a@aaaaaaaa com&uid=10&role= admin
    input = (b'a@aaaaaaaa' + b'admin' + b'\x0b' * 11).decode('ascii')
    ct2 = encrypt_profile(input)
    ct2 = to_blocks(ct2, 16)
    cut_and_paste = ct1[:]
    cut_and_paste[-1] = ct2[1]
    cut_and_paste = b''.join(cut_and_paste)
    decrypted = decrypt_profile(cut_and_paste)
    print(decrypted)
    assert decrypted['role'] == 'admin'
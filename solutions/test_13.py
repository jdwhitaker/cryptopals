import pytest
import cryptopals

key = cryptopals.get_aes_key()

def parse_kv(s):
    items = s.split('&')
    output = {}
    for i in items:
        k, v = i.split('=') 
        output[k] = v
    print(output)
    return output

def profile_for(email):
    blacklist = ['&', '=']
    for c in blacklist:
        if c in email:
            raise Exception(f'Invalid character "{c}" in email "{email}"')
    uid = '10'
    role = 'user'
    d = {
        'email': email,
        'uid': uid,
        'role': role
    }
    output = '&'.join([k + '=' + v for k,v in d.items()])
    return output

def encrypt_profile(email):
    profile = profile_for(email)
    profile = cryptopals.pkcs7_padding(profile.encode('ascii'), len(key))
    return cryptopals.aes_ecb_encrypt(profile, key)

def decrypt_profile(profile):
    decrypted = cryptopals.decrypt_ecb(profile, key)
    decrypted = cryptopals.pkcs7_unpad(decrypted)
    decrypted = decrypted.decode('ascii')
    print('decrypted: ', decrypted)
    return parse_kv(decrypted)

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
    ct1 = cryptopals.to_blocks(ct1, 16)
    # email=a@aaaaaaaa com&uid=10&role= admin
    input = (b'a@aaaaaaaa' + b'admin' + b'\x0b' * 11).decode('ascii')
    ct2 = encrypt_profile(input)
    ct2 = cryptopals.to_blocks(ct2, 16)
    cut_and_paste = ct1[:]
    cut_and_paste[-1] = ct2[1]
    cut_and_paste = b''.join(cut_and_paste)
    decrypted = decrypt_profile(cut_and_paste)
    print(decrypted)
    assert decrypted['role'] == 'admin'
import random
from ..challenge_9.solution import pkcs7_padding
from ...set_1.challenge_7.solution import decrypt_ecb
from ..challenge_10.solution import aes_ecb_encrypt
from ..challenge_12.solution import get_random_aes_key

key = get_random_aes_key()

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
    profile = pkcs7_padding(profile.encode('ascii'), len(key))
    return aes_ecb_encrypt(profile, key)

def decrypt_profile(profile):
    decrypted = decrypt_ecb(profile, key)
    decrypted = decrypted.decode('ascii')
    print('decrypted: ', decrypted)
    return parse_kv(decrypted)
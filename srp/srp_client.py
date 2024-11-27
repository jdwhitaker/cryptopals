import sys
import os
sys.path.append(os.getcwd() + '/./')
import requests
import pprint
import cryptopals
import base64

URL = 'http://localhost:8000/login'
email = 'justinwhitaker@protonmail.com'

N = cryptopals.DH_NIST_P
g = 2 
k = 3

sender_state = {}
def login(password=None):
    global sender_state
    if password == None:
        password = input(f"Password for {email}: ")
        password = bytes(password, 'utf-8')
    msg = 0
    print(f"\nsrp_client:{msg}")
    keys = cryptopals.diffie_hellman_keygen(p=N, g=g)
    sender_state = {
        'email': 'justinwhitaker@protonmail.com',
        'A': keys['public'],
        'a': keys['private']
    }
    pprint.pprint(sender_state)
    r = requests.post(URL, json={
        'email': sender_state['email'],
        'A': str(sender_state['A']),
        'msg': str(msg+1)
    })
    data = r.json()
    msg = data['msg']
    assert msg == 2
    sender_state['salt'] = base64.b64decode(data['salt'])
    sender_state['B'] = int(data['B'])
    u = int.from_bytes(cryptopals.sha256(sender_state['A'] + sender_state['B']))
    x = int.from_bytes(cryptopals.sha256(sender_state['salt'] + password))
    S = pow(sender_state['B'] - k * pow(g,x,N), sender_state['a']+u*x, N)
    K = cryptopals.sha256(cryptopals.int2bytes(S))
    sender_state['K'] = K
    hmac = cryptopals.get_hmac(key=K, message=sender_state['salt'], hash=cryptopals.sha256, block_size=64)
    r = requests.post(URL, json={
        'email': sender_state['email'],
        'hmac': hmac,
        'msg': str(msg+1)
    })
    data = r.json()
    assert data['msg'] == 4
    if data['OK'] == True:
        print('Login successful!')
        return True
    else:
        print('Login failed :(')
        return False

if __name__ == '__main__':
    login()
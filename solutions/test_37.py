import subprocess
import srp
import srp.srp_client
import time
import os
import cryptopals
import pprint
import requests
import base64

URL = 'http://localhost:8000/login'
email = 'justinwhitaker@protonmail.com'
N = cryptopals.DH_NIST_P
g = 2 
k = 3

sender_state = {}
def exploit(A=0):
    global sender_state
    msg = 0
    print(f"exploit:{msg}")
    sender_state = {
        'email': 'justinwhitaker@protonmail.com',
    }
    r = requests.post(URL, json={
        'email': sender_state['email'],
        'A': str(A),
        'msg': str(msg+1)
    })
    data = r.json()
    msg = data['msg']
    assert msg == 2
    sender_state['salt'] = base64.b64decode(data['salt'])
    sender_state['B'] = int(data['B'])
    S = 0
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

def test_37():
    cmd = "flask run --reload -h 0.0.0.0 -p 8000"
    env = os.environ.copy()
    env['FLASK_APP'] = './srp/srp_server.py'
    p = subprocess.Popen(cmd.split(' '), env=env)
    try:
        time.sleep(3)
        assert srp.srp_client.login(password=b'Iliketurtles1') == False
        assert srp.srp_client.login(password=b'Iliketurtles1!') == True
        assert exploit() == True
        assert exploit(A=N) == True
        assert exploit(A=N*2) == True
        p.terminate()
    except Exception as e:
        print(e)
        p.terminate()
        assert True == False
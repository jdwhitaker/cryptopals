from flask import Flask, request, jsonify
import pprint
import random
import base64
import sys
import os
sys.path.append(os.getcwd() + '/./')
import cryptopals

N = cryptopals.DH_NIST_P
g = 2 
k = 3

creds = {
    'justinwhitaker@protonmail.com': b'Iliketurtles1!'
}


app = Flask(__name__)

state = {}

def reset(ip, email):
    global state
    if not ip in state:
        state[ip] = {}
    if not email in state[ip]:
        state[ip][email] = {}
    state[ip][email] = {}
    return

def set(ip, email, key, value):
    global state
    if not ip in state:
        state[ip] = {}
    if not email in state[ip]:
        state[ip][email] = {}
    if not key in state[ip][email]:
        state[ip][email][key] = {}
    state[ip][email][key] = value
    return

def get(ip, email, key):
    global state
    if not ip in state:
        state[ip] = {}
    if not email in state[ip]:
        state[ip][email] = {}
    if not key in state[ip][email]:
        state[ip][email][key] = {}
    return state[ip][email][key]

@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr
    data = request.get_json()
    print(data)
    email = data['email']
    msg = int(data['msg'])
    password = creds[email]
    if msg == 1: 
        salt = cryptopals.get_aes_key()
        x = int.from_bytes(cryptopals.sha256(salt + password))
        v = pow(g, x, N)
        set(ip, email, 'salt', salt)
        set(ip, email, 'v', v)
        set(ip, email, 'x', x)
    assert msg in [1,3]
    if msg == 1:
        keys = cryptopals.diffie_hellman_keygen(p=N, g=g)
        set(ip, email, 'b', keys['private'])
        set(ip, email, 'B', ((k*get(ip, email, 'v')) + pow(g, keys['private'], N)) % N)
        set(ip, email, 'A', int(data['A']))
        set(ip, email, 'email', keys['private'])
        u = int.from_bytes(cryptopals.sha256(get(ip, email, 'A') + get(ip,email,'B')))
        S = pow(get(ip,email,'A') * pow(v,u,N), get(ip,email,'b'), N)
        K = cryptopals.sha256(cryptopals.int2bytes(S))
        set(ip,email,'K', K)
        return jsonify({
            'salt': base64.b64encode(get(ip,email,'salt')).decode('utf-8'),
            'B': str(get(ip,email,'B')),
            'msg': msg+1
        })
    if msg == 3:
        hmac = data['hmac']
        hmac_ = cryptopals.get_hmac(key=get(ip,email,'K'), message=get(ip,email,'salt'), hash=cryptopals.sha256, block_size=64)
        print(hmac)
        print(hmac_)
        if hmac == hmac_:
            return jsonify({
                'OK': True,
                'msg': msg+1
            }), 200
        else:
            return jsonify({
                'OK': False,
                'msg': msg+1
            }), 403
    return "Error", 400

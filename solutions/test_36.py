import cryptopals
import pprint
import random
import hashlib

def sha256(v):
    if type(v) == int:
        v = cryptopals.int2bytes(v)
    hasher = hashlib.sha256()
    hasher.update(v)
    return hasher.digest()

N = cryptopals.DH_NIST_P
g = 2 
k = 3

password = b'Iliketurtles1!'

sender_state = {}
def srp_client(args={}, msg=0, mitm=False):
    global sender_state
    print(f"\nsrp_client:{msg}")
    pprint.pprint({'msg': msg, 'args': args})
    if msg == 0: 
        keys = cryptopals.diffie_hellman_keygen(p=N, g=g)
        sender_state = {
            'email': b'justinwhitaker@protonmail.com',
            'A': keys['public'],
            'a': keys['private']
        }
    pprint.pprint(sender_state)
    assert msg in [0,2,4]
    send = srp_server
    if msg == 0:
        return send({
            'email': sender_state['email'],
            'A': sender_state['A']
        }, msg=msg+1, mitm=mitm)
    if msg == 2:
        sender_state['salt'] = args['salt']
        sender_state['B'] = args['B']
        u = int.from_bytes(sha256(sender_state['A'] + sender_state['B']))
        x = int.from_bytes(sha256(sender_state['salt'] + password))
        S = pow(sender_state['B'] - k * pow(g,x,N), sender_state['a']+u*x, N)
        K = sha256(cryptopals.int2bytes(S))
        sender_state['K'] = K
        hmac = cryptopals.get_hmac(key=K, message=sender_state['salt'], hash=sha256, block_size=64)
        return send({
            'hmac': hmac
        }, msg=msg+1, mitm=mitm)
    if msg == 4:
        return args['OK']

receiver_state = {}
def srp_server(args={}, msg=0, mitm=False):
    global receiver_state
    print(f"\nsrp_server:{msg}")
    pprint.pprint({'msg': msg, 'args': args})
    if msg == 1: 
        salt = cryptopals.int2bytes(random.randint(0, 2**8))
        x = int.from_bytes(sha256(salt + password))
        v = pow(g, x, N)
        receiver_state = {
            'salt': salt,
            'v': v,
            'x': x
        }
    pprint.pprint(receiver_state)
    assert msg in [1,3]
    send = srp_client
    if msg == 1:
        keys = cryptopals.diffie_hellman_keygen(p=N, g=g)
        receiver_state['b'] = keys['private']
        receiver_state['B']= ((k*receiver_state['v']) + pow(g, keys['private'], N)) % N
        receiver_state['A'] = args['A']
        receiver_state['email'] = args['email']
        u = int.from_bytes(sha256(receiver_state['A'] + receiver_state['B']))
        S = pow(receiver_state['A'] * pow(v,u,N), receiver_state['b'], N)
        K = sha256(cryptopals.int2bytes(S))
        receiver_state['K'] = K
        return send({
            'salt': receiver_state['salt'],
            'B': receiver_state['B']
        }, msg=msg+1, mitm=mitm)
    if msg == 3:
        hmac = args['hmac']
        hmac_ = cryptopals.get_hmac(key=receiver_state['K'], message=receiver_state['salt'], hash=sha256, block_size=64)
        print(hmac)
        print(hmac_)
        assert hmac == hmac_
        return send({
            'OK': True
        }, msg=msg+1, mitm=mitm)

def test_36():
    assert srp_client()
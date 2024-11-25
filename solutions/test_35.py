import cryptopals
import sha1
import pprint

mitm_state = {}
def dh_mitm_g1(args={}, msg=0, mitm=None):
    global mitm_state
    print(f"dh_mitm_g1:{msg}")
    pprint.pprint({'msg': msg, 'args': args})
    if msg == 1: mitm_state = {}
    pprint.pprint(mitm_state)
    assert msg in [0,1,2,3,4,5,6]
    mitm = dh_mitm_g1
    if msg == 1:
        mitm_state['p'] = args['p']
        mitm_state['g'] = 1
        return dh_recv({
            'p': mitm_state['p'],
            'g': mitm_state['g']
        }, msg=msg, mitm=mitm)
    if msg == 2: 
        return dh_send(args, msg=msg, mitm=mitm)
    if msg == 3:
        mitm_state['A'] = args['A']
        return dh_recv(args, msg=msg, mitm=mitm)
    if msg == 4:
        return dh_send(args, msg=msg, mitm=mitm)
    if msg == 5:
        # A's session key is 1
        k = bytes.fromhex(sha1.sha1(cryptopals.int2bytes(1)))[:16]
        ct = args['ct']
        iv = ct[-16:]
        ct = ct[:-16]
        pt = cryptopals.pkcs7_unpad(cryptopals.aes_cbc_decrypt(ciphertext=ct, key=k, iv=iv))
        return b'cracked: ' + pt

def dh_mitm_gp(args={}, msg=0, mitm=None):
    global mitm_state
    print(f"dh_mitm_gp:{msg}")
    pprint.pprint({'msg': msg, 'args': args})
    if msg == 1: mitm_state = {}
    pprint.pprint(mitm_state)
    assert msg in [0,1,2,3,4,5,6]
    mitm = dh_mitm_gp
    if msg == 1:
        mitm_state['p'] = args['p']
        mitm_state['g'] = args['p']
        return dh_recv({
            'p': mitm_state['p'],
            'g': mitm_state['g']
        }, msg=msg, mitm=mitm)
    if msg == 2: 
        return dh_send(args, msg=msg, mitm=mitm)
    if msg == 3:
        mitm_state['A'] = args['A']
        return dh_recv(args, msg=msg, mitm=mitm)
    if msg == 4:
        return dh_send(args, msg=msg, mitm=mitm)
    if msg == 5:
        # A's session key is 0
        k = bytes.fromhex(sha1.sha1(cryptopals.int2bytes(0)))[:16]
        ct = args['ct']
        iv = ct[-16:]
        ct = ct[:-16]
        pt = cryptopals.pkcs7_unpad(cryptopals.aes_cbc_decrypt(ciphertext=ct, key=k, iv=iv))
        return b'cracked: ' + pt

def dh_mitm_gpminus1(args={}, msg=0, mitm=None):
    global mitm_state
    print(f"dh_mitm_gpminus1:{msg}")
    pprint.pprint({'msg': msg, 'args': args})
    if msg == 1: mitm_state = {}
    pprint.pprint(mitm_state)
    assert msg in [0,1,2,3,4,5,6]
    mitm = dh_mitm_gpminus1
    if msg == 1:
        mitm_state['p'] = args['p']
        mitm_state['g'] = args['p'] - 1
        return dh_recv({
            'p': mitm_state['p'],
            'g': mitm_state['g']
        }, msg=msg, mitm=mitm)
    if msg == 2: 
        return dh_send(args, msg=msg, mitm=mitm)
    if msg == 3:
        mitm_state['A'] = args['A']
        return dh_recv(args, msg=msg, mitm=mitm)
    if msg == 4:
        return dh_send(args, msg=msg, mitm=mitm)
    if msg == 5:
        # A's session key is p-1
        k = bytes.fromhex(sha1.sha1(cryptopals.int2bytes(mitm_state['g'])))[:16]
        ct = args['ct']
        iv = ct[-16:]
        ct = ct[:-16]
        pt = cryptopals.pkcs7_unpad(cryptopals.aes_cbc_decrypt(ciphertext=ct, key=k, iv=iv))
        return b'cracked: ' + pt

sender_state = {}
def dh_send(args={}, msg=0, mitm=False):
    global sender_state
    print(f"dh_send:{msg}")
    pprint.pprint({'msg': msg, 'args': args})
    if msg == 0: sender_state = {}
    pprint.pprint(sender_state)
    assert msg in [0,2,4,6]
    recv = mitm if mitm else dh_recv
    if msg == 0:
        sender_state['p'] = cryptopals.DH_NIST_P
        sender_state['g'] = cryptopals.DH_NIST_G
        return recv({
            'p': sender_state['p'],
            'g': sender_state['g'],
        }, msg=msg+1, mitm=mitm)
    if msg == 2:
        a_keys = cryptopals.diffie_hellman_keygen(sender_state['p'], sender_state['g'])
        sender_state['a'] = a_keys['private']
        sender_state['A'] = a_keys['public']
        assert args['ACK'] == True
        return recv({
            'A': sender_state['A']
        }, msg=msg+1, mitm=mitm)
    if msg == 4:
        sender_state['B'] = args['B']
        s = cryptopals.diffie_hellman_session(sender_state['a'], sender_state['B'], sender_state['p'])
        sender_state['s'] = s
        k = bytes.fromhex(sha1.sha1(s))[:16]
        sender_state['k'] = k
        iv = cryptopals.get_aes_key()
        ct = cryptopals.aes_cbc_encrypt(input=cryptopals.pkcs7_padding(b'i like turtles', 16), key=k, iv=iv) + iv
        return recv({'ct': ct}, msg=msg+1, mitm=mitm)
    if msg == 6:
        ct = args['ct']
        iv = ct[-16:]
        ct = ct[:-16]
        pt = cryptopals.aes_cbc_decrypt(ciphertext=ct, key=sender_state['k'], iv=iv)
        pt = cryptopals.pkcs7_unpad(pt)
        return pt

receiver_state = {}
def dh_recv(args={}, msg=0, mitm=False):
    global receiver_state
    print(f"dh_recv:{msg}")
    pprint.pprint({'msg': msg, 'args': args})
    if msg == 1: receiver_state = {}
    pprint.pprint(receiver_state)
    assert msg in [1,3,5]
    send = mitm if mitm else dh_send
    if msg == 1:
        receiver_state['p'] = args['p']
        receiver_state['g'] = args['g']
        return send({
            'ACK': True
        }, msg = msg + 1, mitm=mitm)
    if msg == 3:
        b_keys = cryptopals.diffie_hellman_keygen(receiver_state['p'], receiver_state['g'])
        receiver_state['b'] = b_keys['private']
        receiver_state['B'] = b_keys['public']
        receiver_state['A'] = args['A']
        return send({
            'B': receiver_state['B']
        }, msg = msg + 1, mitm=mitm)
    if msg == 5:
        s = cryptopals.diffie_hellman_session(receiver_state['b'], receiver_state['A'], p=receiver_state['p'])
        receiver_state['s'] = s
        k = bytes.fromhex(sha1.sha1(s))[:16]
        receiver_state['k'] = k
        ct = args['ct']
        iv = ct[-16:]
        ct = ct[:-16]
        pt = cryptopals.aes_cbc_decrypt(ciphertext=ct, key=k, iv=iv)
        pt = cryptopals.pkcs7_unpad(pt)
        iv_ = cryptopals.get_aes_key()
        ct_ = cryptopals.aes_cbc_encrypt(input=cryptopals.pkcs7_padding(pt, 16), key=k, iv=iv_)
        ct_ = ct_ + iv_
        return send({'ct': ct_}, msg=msg+1, mitm=mitm)

def test_35():
    print()
    assert dh_send(mitm=False) == b'i like turtles'
    print()
    assert dh_send(mitm=dh_mitm_g1) == b'cracked: i like turtles'
    print()
    assert dh_send(mitm=dh_mitm_gp) == b'cracked: i like turtles'
    print()
    assert dh_send(mitm=dh_mitm_gpminus1) == b'cracked: i like turtles'
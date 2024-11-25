import cryptopals
import sha1

a_keys = cryptopals.diffie_hellman_keygen()
b_keys = cryptopals.diffie_hellman_keygen()

sender_state = {}
def dh_send(args={}, msg=0, mitm=False):
    global sender_state
    print(f"dh_send: msg={msg}, args={args}")
    print(sender_state)
    assert msg in [0,2,4]
    recv = dh_mitm if mitm else dh_recv
    if msg == 0:
        sender_state = {}
        sender_state['p'] = cryptopals.DH_NIST_P
        sender_state['g'] = cryptopals.DH_NIST_G
        return recv({
            'p': sender_state['p'],
            'g': sender_state['g'],
            'A': a_keys['public']
        }, msg=1, mitm=mitm)
    if msg == 2:
        sender_state['B'] = args['B']
        s = cryptopals.diffie_hellman_session(a_keys['private'], sender_state['B'], sender_state['p'])
        sender_state['s'] = s
        k = bytes.fromhex(sha1.sha1(s))[:16]
        sender_state['k'] = k
        iv = cryptopals.get_aes_key()
        ct = cryptopals.aes_cbc_encrypt(input=cryptopals.pkcs7_padding(b'i like turtles', 16), key=k, iv=iv) + iv
        return recv({'ct': ct}, msg=3, mitm=mitm)
    if msg == 4:
        ct = args['ct']
        print('ct: ', ct)
        iv = ct[-16:]
        print('iv: ', iv)
        ct = ct[:-16]
        print('ct: ', ct)
        pt = cryptopals.aes_cbc_decrypt(ciphertext=ct, key=sender_state['k'], iv=iv)
        print(pt)
        pt = cryptopals.pkcs7_unpad(pt)
        print(pt)
        return pt


receiver_state = {}
def dh_recv(args={}, msg=0, mitm=False):
    global receiver_state
    print(f"dh_recv: msg={msg}, args={args}")
    print(receiver_state)
    assert msg in [1,3]
    send = dh_mitm if mitm else dh_send
    if msg == 1:
        receiver_state = {}
        receiver_state['p'] = args['p']
        receiver_state['g'] = args['g']
        receiver_state['A'] = args['A']
        receiver_state['B'] = b_keys['public']
        return send({
            'B': receiver_state['B']
        }, msg=2, mitm=mitm)
    if msg == 3:
        s = cryptopals.diffie_hellman_session(b_keys['private'], receiver_state['A'], p=receiver_state['p'])
        receiver_state['s'] = s
        k = bytes.fromhex(sha1.sha1(s))[:16]
        receiver_state['k'] = k
        ct = args['ct']
        iv = ct[-16:]
        ct = ct[:-16]
        pt = cryptopals.aes_cbc_decrypt(ciphertext=ct, key=k, iv=iv)
        print(pt)
        pt = cryptopals.pkcs7_unpad(pt)
        print(pt)
        iv_ = cryptopals.get_aes_key()
        ct_ = cryptopals.aes_cbc_encrypt(input=cryptopals.pkcs7_padding(pt, 16), key=k, iv=iv_)
        ct_ = ct_ + iv_
        return send({'ct': ct_}, msg=4, mitm=mitm)

mitm_state = {}
def dh_mitm(args={}, msg=0, mitm=True):
    global mitm_state
    print(f"dh_mitm: msg={msg}, args={args}")
    print(mitm_state)
    assert msg in [0,1,2,3,4]
    if msg == 1: 
        mitm_state = {}
        mitm_state['p'] = args['p']
        mitm_state['g'] = args['g']
        return dh_recv({
            'p': mitm_state['p'],
            'g': mitm_state['g'],
            'A': mitm_state['p']
        }, msg=1, mitm=True)
    if msg == 2:
        return dh_send({
            'B': mitm_state['p']
        }, msg=2, mitm=True)
    if msg == 3:
        return dh_recv(args, msg=3, mitm=True)
    if msg == 4:
        ct = args['ct']
        print('ct: ', ct)
        iv = ct[-16:]
        print('iv: ', iv)
        ct = ct[:-16]
        print('ct: ', ct)
        pt = cryptopals.aes_cbc_decrypt(ciphertext=ct, key=sender_state['k'], iv=iv)
        print(pt)
        pt = cryptopals.pkcs7_unpad(pt)
        print(pt)
        return b'cracked: ' + pt


def test_34():
    print()
    assert dh_send(mitm=False) == b'i like turtles'
    print()
    assert dh_send(mitm=True) == b'cracked: i like turtles'
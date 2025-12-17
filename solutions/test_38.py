import subprocess
import srp
import srp.srp_client
import time
import os
import cryptopals
import pprint
import requests
import base64


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

class Server:
    email = b'justinwhitaker@protonmail.com'
    password = b'Iliketurtles1!'

    def __init__(self):
        self.salt = cryptopals.get_aes_key()
        self.pwhash = int.from_bytes(cryptopals.sha256(self.salt + self.password))
        keys = cryptopals.diffie_hellman_keygen(p=N, g=g)
        self.public_key = keys['public']
        self.private_key = keys['private']
        self.dh_param = pow(g, self.pwhash, N)
        print('Server (init)')
        pprint.pprint({
            'x': self.pwhash,
            'v': self.dh_param
        })
        print()

    def handle_msg_1(self, email, client_public_key):
        assert email == self.email
        self.client_public_key = client_public_key
        self.nonce = random.randint(1, 2**128)
        print('Server -> Client (2): ')
        pprint.pprint({
            'salt': self.salt,
            'B': self.public_key,
            'u': self.nonce,
        })
        print()
        return {
            'salt': self.salt,
            'B': self.public_key,
            'u': self.nonce,
        }

    def handle_msg_3(self, hmac):
        secret_key = pow(
            self.client_public_key * pow(self.dh_param, self.nonce, N), 
            self.private_key, 
            N
        )
        self.secret_key = cryptopals.sha256(cryptopals.int2bytes(secret_key))
        print('Server:')
        pprint.pprint({
            'S': secret_key,
            'K': self.secret_key,
        })
        print()
        hmac_ = cryptopals.get_hmac(key=self.secret_key, message=self.salt, hash=cryptopals.sha256, block_size=64)
        return hmac == hmac_

class Client:
    email = b'justinwhitaker@protonmail.com'
    password = b'Iliketurtles1!'

    def __init__(self, server = None):
        keys = cryptopals.diffie_hellman_keygen(p=N, g=g)
        self.public_key = keys['public']
        self.private_key = keys['private']
        if server == None:
            self.server = Server()
        else:
            self.server = server

    def send_msg_1(self):
        print('Client -> Server (1):')
        pprint.pprint({
            'I': self.email,
            'A': self.public_key,
        })
        print()
        return self.server.handle_msg_1(self.email, self.public_key)
    
    def handle_msg_2(self, salt, server_public_key, nonce):
        pwhash = int.from_bytes(cryptopals.sha256(salt + self.password))
        secret_key = pow(
            server_public_key, 
            self.private_key + nonce * pwhash, 
            N
        )
        self.secret_key = cryptopals.sha256(cryptopals.int2bytes(secret_key))
        hmac = cryptopals.get_hmac(key=self.secret_key, message=salt, hash=cryptopals.sha256, block_size=64)
        print('Client:')
        pprint.pprint({
            'x': pwhash,
            'S': secret_key,
            'K': self.secret_key,
        })
        print()
        return {
            'I': self.email,
            'hmac': hmac,
        }
    
    def send_msg_3(self, hmac):
        return self.server.handle_msg_3(hmac)
    
    def handle_msg_4(self, ok):
        assert ok == True
        print('Login successful!')

class MITM:
    wordlist = [
        b'Iliketurtles11',
        b'Iliketurtles2!',
        b'Iliketurtles1!',
        b'Iliketurtles2!',
    ]
    def __init__(self):
        self.salt = cryptopals.get_aes_key()
        keys = cryptopals.diffie_hellman_keygen(p=N, g=g)
        self.public_key = keys['public']
        self.private_key = keys['private']

    def handle_msg_1(self, email, client_public_key):
        self.client_public_key = client_public_key
        self.nonce = 1
        print('MITM -> Client (2): ')
        pprint.pprint({
            'salt': self.salt,
            'B': self.public_key,
            'u': self.nonce,
        })
        print()
        return {
            'salt': self.salt,
            'B': self.public_key,
            'u': self.nonce,
        }

    def handle_msg_3(self, hmac):
        for pw in self.wordlist:
            pwhash = int.from_bytes(cryptopals.sha256(self.salt + pw))
            dh_param = pow(g, pwhash, N)
            secret_key = pow(
                self.client_public_key * pow(dh_param, self.nonce, N), 
                self.private_key, 
                N
            )
            secret_key = cryptopals.sha256(cryptopals.int2bytes(secret_key))
            hmac_ = cryptopals.get_hmac(key=secret_key, message=self.salt, hash=cryptopals.sha256, block_size=64)
            if hmac == hmac_:
                print(f'Password found: {pw.decode("utf-8")}')
                return True
        return False


def test_38():
    client = Client()
    r = client.send_msg_1()
    r = client.handle_msg_2(r['salt'], r['B'], r['u'])
    r = client.send_msg_3(r['hmac'])
    client.handle_msg_4(r)

    client = Client(server=MITM())
    r = client.send_msg_1()
    r = client.handle_msg_2(r['salt'], r['B'], r['u'])
    r = client.send_msg_3(r['hmac'])
    client.handle_msg_4(r)

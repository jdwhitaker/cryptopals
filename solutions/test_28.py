import cryptopals
import sha1


def get_mac(key, message):
    return sha1.sha1(key + message)

def authn(key, message, mac):
    return get_mac(key, message) == mac

def test_28():
    key = cryptopals.get_aes_key()
    message = b"i like turtles"
    mac = get_mac(key, message)
    tampered_message = b"i like turtle "
    assert authn(key, tampered_message, mac) == False
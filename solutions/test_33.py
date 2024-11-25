import cryptopals
import random

def test_33():
    a = cryptopals.diffie_hellman_keygen()
    print(a)
    b = cryptopals.diffie_hellman_keygen()
    print(b)
    session_key_a = cryptopals.diffie_hellman_session(a['private'], b['public'])
    session_key_b = cryptopals.diffie_hellman_session(b['private'], a['public'])
    print(session_key_a)
    assert session_key_a == session_key_b
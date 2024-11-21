import cryptopals
import md4
import struct

def get_mac(key, message):
    mac = md4.MD4()
    mac.add(key+message)
    return mac.finish().hex()


def get_mpad(message_byte_length):
    l = message_byte_length
    return b"\x80" + b"\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8)

def authn(key, message, mac):
    correct_mac = get_mac(key, message)
    is_authenticated  = mac == correct_mac
    return is_authenticated

def extend_md4(prior_hash, prior_message_length, extension): 
    registers = [int.from_bytes(bytes.fromhex(prior_hash)[i:i+4][::-1]) for i in range(0,16,4)]
    mpad = get_mpad(prior_message_length)
    crack_md4 = md4.MD4(b"", prior_message_length+len(mpad), *registers)
    crack_md4.add(extension)
    return crack_md4.finish().hex(), mpad+extension


def test_md4():
    test = (
            (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
            (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
            (b"message digest", "d9130a8164549fe818874806e1c7014b"),
            (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
            (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
            (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536")
    )
    md = md4.MD4()
    for t, h in test:
        md.add(t)
        d = md.finish()
        assert d.hex() == h

def test_30():
    key = cryptopals.get_aes_key()
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = get_mac(key, message)
    assert authn(key, message, mac)
    crack_digest, extension = extend_md4(mac, len(key)+len(message), b';admin=true')
    assert authn(key, message + extension, crack_digest)
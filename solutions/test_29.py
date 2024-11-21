import cryptopals
import sha1
import struct


def get_mac(key, message):
    mac = sha1.sha1(key + message)
    return mac

def authn(key, message, mac):
    correct_mac = get_mac(key, message)
    is_authenticated  = mac == correct_mac
    if is_authenticated:
        print("authenticated message ", message)
    return is_authenticated

def get_mpad(message_byte_length):
    _pad = b''
    # append the bit '1' to the message
    _pad += b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    _pad += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message_bit_length = message_byte_length * 8
    _pad += struct.pack(b'>Q', message_bit_length)
    return _pad

def extend_sha1(prior_hash, prior_message_length, extension): 
    registers = [int(prior_hash[i:i+8], 16) for i in range(0,40,8)]
    crack_sha1 = sha1.Sha1Hash(*registers)
    mpad = get_mpad(prior_message_length)
    crack_sha1._message_byte_length = prior_message_length + len(mpad)
    crack_sha1.update(extension)
    crack_digest = crack_sha1.hexdigest()
    return crack_digest, mpad+extension


def test_29():
    key = cryptopals.get_aes_key()
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = get_mac(key, message)
    assert authn(key, message, mac)
    crack_digest, extension = extend_sha1(mac, len(key)+len(message), b';admin=true')
    assert authn(key, message + extension, crack_digest)
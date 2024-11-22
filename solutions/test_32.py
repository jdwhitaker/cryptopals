import cryptopals
import sha1
import numpy
import threading


current_time = 0

def get_hmac(key, message, hash, block_size):
    def compute_block_sized_key(key, hash, block_size):
        if len(key) > block_size:
            key = hash(key)
        if len(key) < block_size:
            return key + b"\x00" * (block_size - len(key))
    
    block_sized_key = compute_block_sized_key(key, hash, block_size)
    o_key_pad = cryptopals.fixed_xor(block_sized_key, b"\x5c" * block_size)
    i_key_pad = cryptopals.fixed_xor(block_sized_key, b"\x36" * block_size)
    tmp = hash(i_key_pad + message)
    tmp2 = hash(o_key_pad + tmp)
    return tmp2.hex()

def test_hmac():
    #key = bytes('xxxthisisasecret', 'utf-8')
    key = b"x"
    msg = b"x"
    hmac = get_hmac(key, msg, lambda i: bytes.fromhex(sha1.sha1(i)), 64)
    assert hmac == '8b6ff74fa7182a90ac20616816f7b8814a429f7c'

key = cryptopals.get_aes_key()
def insecure_compare(file, signature):
    global current_time
    hmac = get_hmac(key, file, lambda i: bytes.fromhex(sha1.sha1(i)), 64)
    hmac = bytes.fromhex(hmac)
    signature = bytes.fromhex(signature)
    for i in range(len(hmac)):
        if i == len(signature):
            return False
        provided = signature[i]
        true = hmac[i]
        if provided != true:
            return False
        current_time += 5
    return True

def timeit(f, *args):
    start = current_time
    f(*args)
    end = current_time
    duration = end - start
    return duration

def test_32():
    assert insecure_compare(b'i like turtles', '868e7eea27cfbbd7412160bd86f73578200fb19a')
    print()
    prior_input = [0 for _ in range(20)]
    for i in range(20):
        times = [0 for _ in range(256)]
        threads = []

        def thread_f(j, guess):
            for _ in range(10):
                delay = timeit(insecure_compare, b'i like turtles', guess)
                times[j] += delay

        for j in range(256):
            guess = prior_input[::]
            guess[i] = j
            guess = bytes(guess).hex()
            thread = threading.Thread(thread_f(j, guess))
            threads.append(thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        cracked = int(numpy.argmax(times))
        prior_input[i] = cracked
        print(bytes(prior_input).hex())
    assert insecure_compare(b'i like turtles', bytes(prior_input).hex())
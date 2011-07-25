import argparse
import json
import os
from Crypto.PublicKey import DSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256
##################################################################################


def get_dsa_key(key):
    """Returns a json version of the key data, b64 encoded BigNums
    """
    return dict(zip(key.keydata, [hex(key.__getattr__(_))[2:-1]
                                  for _ in key.keydata]))


def test_dsa_sign():
    global key
    key = DSA.generate(1024)
    d = get_dsa_key(key)
    M = "This is a test message, OK?"
    K = bytes_to_long(os.urandom(19))+2
    H = SHA256.new(M)
    signature = key.sign(H.digest(), K)
    assert(key.verify(H.digest(), signature))
    d['M'] = M
    d['H'] = H.hexdigest()
    d['K'] = hex(K)[2:-1]
    d['Signature'] = [hex(_)[2:-1] for _ in signature]
    return d


# Copy a JSON.stringify(key.dump()) from the browser
# and see if it works here
test_key = "asdf"


def test_key():
    global key2
    k = [int(test_data[_],16) for _ in ['y', 'g', 'p', 'q', 'x']]
    key2 = key = DSA.construct(k)
    M = "This is a test message, OK?"
    K = bytes_to_long(os.urandom(19))+2
    H = SHA256.new(M)
    signature = key.sign(H.digest(), K)
    assert(key.verify(H.digest(), signature))


if __name__ == '__main__':
    print json.dumps(test_dsa_sign())
    #test_key()

import argparse
import json
import os
from Crypto.PublicKey import DSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256


def get_dsa_key(key):
    """Returns a json version of the key data, b64 encoded BigNums
    """
    return dict(zip(key.keydata, [hex(key.__getattr__(_))[2:-1]
                                  for _ in key.keydata]))


def test_dsa_sign():
    key = DSA.generate(1024)
    d = get_dsa_key(key)
    M = "This is a test message, OK?"
    K = bytes_to_long(os.urandom(19))+2
    H = SHA256.new(M)
    signature = key.sign(H.digest(), K)
    d['M'] = M
    d['H'] = H.hexdigest()
    d['K'] = hex(K)[2:-1]
    d['Signature'] = [hex(_)[2:-1] for _ in signature]
    return d

if __name__ == '__main__':
    print json.dumps(test_dsa_sign())

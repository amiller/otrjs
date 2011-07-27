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


def validate_key(key):
    assert pow(key.g, key.q, key.p) == 1


def generateDSA(p, q, g):
    power = (p-1)/q
    while (1):
        h = 2
        g = pow(h, power, p)
        x = bytes_to_long(os.urandom(20))
        if 0 < x < q:
            break
    y = pow(g, x, p)
    key = DSA.construct((y, g, p, q, x))
    return key


def test_group2():
    global group2_key
    p = """
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
    FFFFFFFF FFFFFFFF
    """
    q = """
    7FFFFFFF FFFFFFFF E487ED51 10B4611A 62633145 C06E0E68
    94812704 4533E63A 0105DF53 1D89CD91 28A5043C C71A026E
    F7CA8CD9 E69D218D 98158536 F92F8A1B A7F09AB6 B6A8E122
    F242DABB 312F3F63 7A262174 D31BF6B5 85FFAE5B 7A035BF6
    F71C35FD AD44CFD2 D74F9208 BE258FF3 24943328 F67329C0
    FFFFFFFF FFFFFFFF
    """
    p = int(''.join(p.split()), 16)
    q = int(''.join(q.split()), 16)
    g = 2
    key = generateDSA(p, q, g)
    validate_key(key)
    group2_key = key


if __name__ == '__main__':
    print json.dumps(test_dsa_sign())
    #test_key()
    #test_group2()

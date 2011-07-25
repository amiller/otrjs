// DSA Signatures in javascript
// July 2011
// Andrew Miller <amiller@dappervision.com>

// This uses the JSBN (Javascript BigNumber) library by Tom Wu.
// JSBN only comes with implementations of RSA and ECC, so I am
// adding DSA.
// https://github.com/jasondavies/jsbn

// Otherwise, this was written by flipping back and forth between
// the PyCrypto DSA.py code and the Wikipedia for DSA.

// This file dsa.js contains all the functionality needed to generate,
// sign, and verfy DSA keys, using prearranged domain parameters.
// To generate such domain parameters, see dsa2.js, but it's slow
// and using Group2 should be a reasonable default.
// "Well-Known Group 2 - A 1024-bit Prime"
// http://xml.resource.org/public/rfc/html/rfc2412.html#anchor48

// "empty" DSA key constructor
function DSAKey() {
    this.p = null;
    this.q = null;
    this.g = null;
    this.y = null;
    this.x = null;
}

// Set the private key fields p, q, g, y from hex strings
function DSASetPrivate(p, q, g, y, x) {
    this.p = new BigInteger(p,16);
    this.q = new BigInteger(q,16);
    this.g = new BigInteger(g,16);
    this.y = new BigInteger(y,16);
    this.x = new BigInteger(x,16);
}

// Set the public key fields p, q, g, y from hex strings
function DSASetPublic(p, q, g, y) {
    this.p = new BigInteger(p,16);
    this.q = new BigInteger(q,16);
    this.g = new BigInteger(g,16);
    this.y = new BigInteger(y,16);
}


// Generate x and y, assuming parameters p, q, g set previously
function DSAGeneratePrivate() {
    var rng = new SecureRandom();
    while (1) {
	var x = new BigInteger(160, rng);
	if (BigInteger.ZERO.compareTo(x) < 0 &&
	    x.compareTo(this.q) < 0)
	    break;
    }
    this.x = x;
    this.y = this.g.modPow(this.x, this.p);
}

// Sign a message digest (using random key K)
function DSASign(Hm, K) {
    if (K == undefined) {
	var rng = new SecureRandom();
	K = new BigInteger(19, rng).add(new BigInteger('2'));
    }
    if (K.compareTo(new BigInteger('2')) < 0 ||
	this.q.compareTo(K) <= 0) {
	throw 'K is not between 2 and q';
    }
    var r = this.g.modPow(K, this.p).mod(this.q);
    var k1 = K.modInverse(this.q)
    var s = k1.multiply(Hm.add(this.x.multiply(r))).mod(this.q);
    return [r,s];
}

function DSAVerify(Hm, Sig) {
    var r = Sig[0];
    var s = Sig[1];
    if (r.compareTo(BigInteger.ZERO) <= 0 || 
	r.compareTo(this.q) >= 0 || 
	s.compareTo(BigInteger.ZERO) <= 0 || 
	s.compareTo(this.q) >= 0) {
	return 0;
    }
    var w = s.modInverse(this.q);
    var u1 = Hm.multiply(w).mod(this.q);
    var u2 = r.multiply(w).mod(this.q);
    var v1 = this.g.modPow(u1, this.p);
    var v2 = this.y.modPow(u2, this.p);
    var v = v1.multiply(v2).mod(this.p).mod(this.q);
    return v.equals(r);
}

function DSADump() {
    return {
	'p': this.p.toString(16),
	'q': this.q.toString(16),
	'g': this.g.toString(16),
	'y': this.y.toString(16),
	'x': this.x.toString(16)
    }	
}


function DSAGroup2() {
    // This is a group that's known to be prime
    // http://xml.resource.org/public/rfc/html/rfc2412.html#anchor48
    var p = "\
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1\
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD\
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245\
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED\
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381\
    FFFFFFFF FFFFFFFF";
    var q = "\
    7FFFFFFF FFFFFFFF E487ED51 10B4611A 62633145 C06E0E68\
    94812704 4533E63A 0105DF53 1D89CD91 28A5043C C71A026E\
    F7CA8CD9 E69D218D 98158536 F92F8A1B A7F09AB6 B6A8E122\
    F242DABB 312F3F63 7A262174 D31BF6B5 85FFAE5B 7A035BF6\
    F71C35FD AD44CFD2 D74F9208 BE258FF3 24943328 F67329C0\
    FFFFFFFF FFFFFFFF";
    this.p = new BigInteger(p, 16);
    this.q = new BigInteger(q, 16);
    this.g = new BigInteger('2');
    this.generatePrivate()
}

function DSAValidateKey() {
    // FIXME Finish key validation here? Add other validation
    if (this.g.modPow(this.q, this.p) != 1)
	throw 'g^q != 1 (modp)';
    return true;
}

DSAKey.prototype.sign = DSASign;
DSAKey.prototype.verify = DSAVerify;
DSAKey.prototype.setPrivate = DSASetPrivate;
DSAKey.prototype.setPublic = DSASetPublic;
DSAKey.prototype.generatePrivate = DSAGeneratePrivate;
DSAKey.prototype.validateKey = DSAValidateKey;
DSAKey.prototype.group2 = DSAGroup2;
DSAKey.prototype.dump = DSADump;
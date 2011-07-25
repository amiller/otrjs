// DSA Signatures in javascript
// July 2011
// Andrew Miller <amiller@dappervision.com>

// This uses the JSBN (Javascript BigNumber) library by Tom Wu.
// JSBN only comes with implementations of RSA and ECC, so I am
// adding DSA.
// https://github.com/jasondavies/jsbn

// Otherwise, this was written by flipping back and forth between
// the PyCrypto DSA.py code and the Wikipedia for DSA.

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

function generateQ(rng, H) {
    // H must return a byte array, NOT a hex digest!
    var S = new BigInteger(160,rng);
    var hash1 = H(S.toString(16));
    var hash2 = H(S.add(BigInteger.ONE).toString(16));
    if (typeof(hash1) != "object")
	throw "Hash function H must return a byte array, not " + typeof(hash1);
    if (typeof(hash2) != "object")
	throw "Hash function H must return a byte array, not " + typeof(hash2);
    var q = BigInteger.ZERO;
    for (var i = 0; i < 20; i++) {
	var c = hash1[i] ^ hash2[i];
	if (i ==  0) c |= 128;
	if (i == 19) c |= 1;
	//q = q.shiftLeft(8);
	q = q.multiply(new BigInteger('256'));
	q = q.add(new BigInteger(String(c)));
    }
    // The JSBN implementation of this uses Rabin-Miller to find strong
    // probable primes
    var TWO = new BigInteger('2');
    while (!q.isProbablePrime(50)) {
	q = q.add(TWO);
    }
    //console.info([TWO.pow(159).compareTo(q), TWO.pow(160).compareTo(q)
    if (TWO.pow(159).compareTo(q) < 0 && TWO.pow(160).compareTo(q) > 0)
	return [S, q];
    throw 'Bad q value generated';
}

// Generate a new random private Parkey B bits long, using hash function H
function DSAGenerate(B, H) {
    if (B < 160) throw 'Key length < 160 bits: ' + B;
    var rng = new SecureRandom();
    var TWO = new BigInteger('2');
    //console.info('p,q');
    while (1) {
	var Sq = generateQ(rng, H);
	var S = Sq[0];
	this.q = Sq[1];
	var n = Math.floor((B-1)/160);
	var N = TWO;
	var V = new Array(n);
	var b = this.q.shiftRight(5).and(new BigInteger('15'));
	var powb = TWO.pow(b);
	var powL1 = TWO.pow(B-1);
	for (var C = 0; C < 4096; C++) {
	    for (var k = 0; k < n+1; k++)
		V[k] = new BigInteger(H(S+
					N.toString(16)+
					k.toString()));
	    var W = V[n].mod(powb);
	    for (k = n-1; k > -1; k--)
		W = W.shiftLeft(160).add(V[k]);
	    var X = W.add(powL1);
	    var p = X.subtract(X.mod(this.q.shiftLeft(1)).subtract(BigInteger.ONE));
	    if (powL1.compareTo(p) <= 0 && p.isProbablePrime(50))
		break;
	    N = N.add(new BigInteger(String(n))).add(BigInteger.ONE);
	}
	if (C < 4096) break;
	console.info('4096 multiples failed');
    }
    this.p = p;
    var power = this.p.subtract(BigInteger.ONE).divide(this.q);
    //console.info('h,g');
    while (1) {
	// FIXME should this be B*8 or just B? doubt it matters,
	// but look at http://pycrypto.cvs.sourceforge.net/viewvc/pycrypto/crypto/PublicKey/DSA.py?revision=1.16&view=markup
	var h = (new BigInteger(B*8,rng)).mod(p.subtract(BigInteger.ONE));
	var g = h.modPow(power, this.p);
	if (BigInteger.ONE.compareTo(h) < 0 &&
	    g.compareTo(BigInteger.ONE) > 0)
	    break;
    }
    this.g = g;
    console.info('g^q mod p: ' + this.g.modPow(this.q, this.p).toString());
    //console.info('x,y');
    while (1) {
	var x = new BigInteger(160,rng);
	if (BigInteger.ZERO.compareTo(x) < 0 && 
	    x.compareTo(this.q) < 0)
	    break;
    }
    this.x = x;
    this.y = this.g.modPow(this.x, this.p);
}

function DSASign(Hm, K) {
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

DSAKey.prototype.sign = DSASign;
DSAKey.prototype.verify = DSAVerify;
DSAKey.prototype.setPrivate = DSASetPrivate;
DSAKey.prototype.setPublic = DSASetPublic;
DSAKey.prototype.generate = DSAGenerate;
DSAKey.prototype.dump = DSADump;
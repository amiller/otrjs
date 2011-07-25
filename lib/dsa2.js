// DSA Signatures in javascript
// July 2011
// Andrew Miller <amiller@dappervision.com>

// This uses the JSBN (Javascript BigNumber) library by Tom Wu.
// JSBN only comes with implementations of RSA and ECC, so I am
// adding DSA.
// https://github.com/jasondavies/jsbn

// Otherwise, this was written by flipping back and forth between
// the PyCrypto DSA.py code and the Wikipedia for DSA.

function DSAGenerateParameters(B, H) {
    // Generate p,q,g
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

DSAKey.prototype.generateParameters = DSAGenerateParameters;
// "empty" RSA key constructor
function DSAKey() {
  this.y = null;
  this.g = null;
  this.p = null;
  this.q = null;
  this.x = null;
}

function DSA_FromObj(obj) {
    // JSON with hex strings
    this.y = new BigInteger(obj.y, 16);
    this.g = new BigInteger(obj.g, 16);
    this.p = new BigInteger(obj.p, 16);
    this.q = new BigInteger(obj.q, 16);
    this.x = new BigInteger(obj.x, 16);
}

function DSA_Sign(M, K) {
    if (K < 2 || this.q <= K) {
	throw 'K is not between 2 and q';
    }
    var r = this.g.modPow(K, this.p).mod(this.q);
    var k1 = K.modInverse(this.q)
    var s = k1.multiply(M.add(this.x.multiply(r))).mod(this.q);
    return [r,s];
}

DSAKey.prototype.sign = DSA_Sign;
DSAKey.prototype.fromObj = DSA_FromObj;

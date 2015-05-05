define(["./BigInt", "../algo/md5"], function (BigInt, md5) {
"use strict";

// shortcuts so we don't need to type Math.blah all the time
var exp = Math.exp,
    pow = Math.pow,
    ln = Math.log, // Math.log is natural logarithm (base e)
    log2 = Math.log2,
    floor = Math.floor,
    ceil = Math.ceil;

// returns a Promise that when resolved has a random prime number of bits length, set the second parameter to true
// to get a provable prime (default) or false to get a probable prime
// the prime number is returned as a BigInt
function Prime(bits, provable) {
    if (provable === undefined) {
        provable = true;
    }
    
    return new Promise((resolve, reject) => {
        try {
            if (provable) {
                resolve(ProvablePrime(bits));
            } else {
                resolve(ProbablePrime(bits));
            }
        } catch (e) {
            reject(e);
        }
    });
}

// returns a random provable Prime number of bits length
// uses Shawe-Taylor as described in FIPS 186-4, Appendix C.6
// CAVEAT: prime provability relies on BigInt.toPrime using a deterministic algorithm, which I have not yet determined is the case
function ProvablePrime(bits) {
    if (!Number.isInteger(bits) || bits <= 0 || bits % 8 != 0) {
        throw new Error("bits must be an integer multiple 8 greater than 0");
    }
    
    // get a starting seed at random based on the approximate security strength of bits
    // length of seed is 2 * strength bits, rounded down to nearest multiple of 8
    // strength equation based on complexity equation for the General Number Field Sieve:
    // https://en.wikipedia.org/wiki/General_number_field_sieve
    var strength = floor(log2(exp(pow(64/9 * (bits - 1) * ln(2), 1/3) * pow(ln((bits - 1) * ln(2)), 2/3))));
    var seed = new Uint8Array(floor(2 * strength / 8));
    
    do {
        seed = crypto.getRandomValues(seed);
    } while (seed[0] & (1 << 7) === 0);
    
    return ST(bits, seed).then(res => res[0]);
}

function ST(length, inputSeed, hashAlgo) {
    // Hash is expected to take a single Uint8Array parameter and return a Promise
    // if none is specified in the params, we assume SHA-256
    // outlen is the bit length of the hash output
    hashAlgo = hashAlgo || "SHA-256";
    var primeSeed = inputSeed;
    var primeGenCounter = 0;
    var c0, iterations, oldCounter;
    
    var Hash = function (m) {
        if (hashAlgo === "MD5" || hashAlgo === "md5") {
            return Promise.resolve(md5(m));
        }
        
        return crypto.subtle.digest(hashAlgo, m);
    };
    
    if (length < 2) {
        throw new Error("length cannot be less than 2");
    }
    
    return Hash(new Uint8Array(1)).then(function (d) {
        return d.byteLength * 8;
    }).then(function (outlen) {
        if (length < 33) {
            // Steps 5 - 13
            return (function Step5() {
                if (primeGenCounter > 4 * length) {
                    throw new Error("Could not find a prime with the given seed");
                }

                return Promise.all([Hash(primeSeed), Hash(BigInt(primeSeed).add(1).toBinaryData().buffer)]).then(function (d) {
                    let c = BigInt(d[0]).xor(d[1]);
                    c = BigInt.two.pow(length - 1).add(c.mod(BigInt.two.pow(length - 1)));
                    c = BigInt.two.multiply(c.divide(2)).add(1);
                    primeGenCounter++;
                    primeSeed = BigInt(primeSeed).add(2).toBinaryData().buffer;
                    
                    // TODO: Figure out if BigInt.isPrime() is a probabalistic test or a deterministic test -- we need the latter here
                    if (c.isPrime()) {
                        return [c, primeSeed, primeGenCounter];
                    } else {
                        return Step5();
                    }
                });
            })();
        } else {
            // Steps 14 - 22
            // TODO: replace with destructuring once chrome supports it
            return ST(ceil(length / 2) + 1, inputSeed).then(function (res) {
                c0 = res[0];
                primeSeed = res[1];
                primeGenCounter = res[2];
                iterations = Math.ceil(length / outlen) - 1;
                oldCounter = primeGenCounter;
                
                return (function Step19(i, x) {
                    return Hash(BigInt(primeSeed).add(i).toBinaryData().buffer).then(function (d) {
                        x = x.add(BigInt(d).multiply(BigInt.two.pow(i * outlen)));
                        
                        if (i < iterations) {
                            return Step19(i + 1, x);
                        } else {
                            return x;
                        }
                    });
                })(0, BigInt.zero).then(function (x) {
                    primeSeed = BigInt(primeSeed).add(iterations).add(1).toBinaryData().buffer;
                    x = BigInt.two.pow(length - 1).add(x.mod(BigInt.two.pow(length - 1)));
                    var dm = x.divmod(BigInt.two.multiply(c0));
                    var t = dm.quotient.add(dm.remainder.isZero() ? 0 : 1);
                    
                    // Steps 23 - 34
                    return (function Step23(t) {
                        if (primeGenCounter > (4 * length) + oldCounter) {
                            throw new Error("Could not find a prime with the given seed");
                        }
                        
                        if (BigInt.two.multiply(t).multiply(c0).add(1).greater(BigInt.two.pow(length))) {
                            let dm = BigInt.two.pow(length - 1).divmod(BigInt.two.multiply(c0));
                            t = dm.quotient.add(dm.remainder.isZero() ? 0 : 1);
                        }
                        
                        let c = BigInt.two.multiply(t).multiply(c0).add(1);
                        primeGenCounter++;
                        
                        return (function Step27(i, a) {
                            return Promise.resolve(Hash(BigInt(primeSeed).add(i).toBinaryData().buffer)).then(function (d) {
                                a = a.add(BigInt(d).multiply(BigInt.two.pow(i * outlen)));
                                
                                if (i < iterations) {
                                    return Step27(i + 1, a);
                                } else {
                                    return a;
                                }
                            });
                        })(0, BigInt.zero).then(function (a) {
                            primeSeed = BigInt(primeSeed).add(iterations).add(1).toBinaryData().buffer;
                            a = BigInt.two.add(a.mod(c.subtract(3)));
                            let z = a.modPow(BigInt.two.multiply(t), c);
                            
                            
                            if (BigInt.gcd(z.subtract(1), c).isUnit() && z.modPow(c0, c).isUnit()) {
                                return [c, primeSeed, primeGenCounter];
                            }
                            
                            t = t.add(1);
                            return Step23(t);
                        });
                    })(t);
                });
            });
        }
    });
}

// expose underpinnings for applications that need them (DSA/RSA keygen would need direct access to ST, for example, as the returned seed/counter are important)
Prime.ProvablePrime = ProvablePrime;
Prime.ST = ST;

return Prime;
});

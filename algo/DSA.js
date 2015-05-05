define(
    ["../util/BigInt", "../util/BinaryData", "../util/Prime", "../util/Base64"],
    function (BigInt, BinaryData, Prime, Base64) {
"use strict";

var _handle = Symbol("[[handle]]");
var _keyMaterial = new WeakMap();
var _uuidKty = "a93954ad-1fa0-4ca8-aab4-c0c9545aff15"; // DSA
var _uuidAlg = {
    DS160: "3e39eeb9-ee43-4455-a07a-fc72941de431", // DSA using SHA-1 (1024 bit key)
    DS256: "5fcb7176-5c49-47b1-8186-5ceac87190f9", // DSA using SHA-256 (2048 bit key)
    other: "f50cdfe6-8f80-4e45-909e-43928017c3a9", // DSA with hash algorithm specified in params
};

function getAlgUuid(d) {
    if (d.N === 160 && d.L === 1024 && d.hash === "SHA-1") {
        return _uuidAlg.DS160;
    } else if (d.N === 256 && d.L === 2048 && d.hash === "SHA-256") {
        return _uuidAlg.DS256;
    } else {
        return _uuidAlg.other;
    }
}

function getAlgName(d) {
    if (d.N === 160 && d.L === 1024 && d.hash === "SHA-1") {
        return "DS160";
    } else if (d.N === 256 && d.L === 2048 && d.hash === "SHA-256") {
        return "DS256";
    } else {
        return "other";
    }
}

function pow2(n) {
    return BigInt.two.pow(n);
}

// Implementation of DSA, according to FIPS 186-4
// The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
// "MAY", and "OPTIONAL" in these comments are to be interpreted as described in RFC 2119.
class DSA {
    // key is the DSA private key, m is the message to sign, k is the per-message secret
    // key MUST be the privateKey object returned from generateKey() or importKey() and MUST be allowed "sign" in its
    //   usages array.
    // m MUST be convertible to BigInt (ArrayBuffer, ArrayBufferView, BinaryData, BigInt, etc.)
    // k MAY be specified. If specified, it MUST be convertible to BigInt. If unspecified, sign() generates a random k
    // returns a Promise that resolves with an object containing two keys r and s that constitute the signature
    static sign(key, m, k) {
        if (key[_handle] === undefined
            || _keyMaterial.get(key[_handle]) === undefined
            || _keyMaterial.get(key[_handle]).type !== "private")
        {
            throw new Error("key must be a DSA privateKey");
        }

        var keyInfo = _keyMaterial.get(key[_handle]);
        var x = keyInfo.key;
        var domInfo = _keyMaterial.get(keyInfo.domain);
        var hashFunc = domInfo.hash;
        var p = domInfo.p;
        var q = domInfo.q;
        var g = domInfo.g;
        var N = domInfo.N;
        var passedK = k !== undefined;
        var outlen, hashLen;

        if (keyInfo.usages.indexOf("sign") === -1) {
            throw new Error("key may not be used for signing");
        }

        var Hash = m => crypto.subtle.digest(hashFunc, m).then(d => new Uint8Array(d.buffer, 0, hashLen));

        return crypto.subtle.digest(hashFunc, new Uint8Array(1)).then(function (d) {
            outlen = d.byteLength;
            hashLen = Math.min(N, outlen) / 8;

            // generate our k if it wasn't given
            if (!passedK) {
                let c = BigInt(crypto.getRandomValues(new Uint8Array((N + 64) / 8)));
                k = c.mod(q.subtract(1)).add(1);
            }

            // compute k^-1, which is the inverse mod q of k
            if (!k.lesser(q)) {
                throw new Error("Per-message secret k too large");
            } else if (!k.greater(0)) {
                throw new Error("Per-message secret k must be greater than 0");
            }

            return (function Step3(i, j, y2, y1) {
                var dm = i.divmod(j);
                var y = y2.subtract(y1.multiply(dm.quotient));

                if (dm.remainder.greater(0)) {
                    return Step3(j, dm.remainder, y1, y);
                } else if (!j.isUnit()) {
                    throw new Error("Could not compute inverse of k");
                } else {
                    return y1.mod(q); // y2 mod a in spec, but we skipped over the part that set y2 = y1, and a = q
                }
            })(q, k, BigInt.zero, BigInt.one);
        }).then(function (ki) {
            var r = g.modPow(k, p).mod(q);

            return Hash(m).then(function (z) {
                var s = ki.multiply(BigInt(z).add(x.multiply(r))).mod(q);

                if (r.isZero() || s.isZero()) {
                    // need a different k
                    if (passedK) {
                        throw new Error("Invalid per-message secret k given");
                    }

                    return DSA.sign(key, m);
                }

                var sig = {r: r, s: s};
                Object.freeze(sig);

                return sig;
            });
        });
    }

    // key is the DSA public key, m is the signed message, s is the signature
    // key MUST be the publicKey object returned from generateKey() or importKey() and MUST allow "verify" in its
    //   usages array.
    // m MUST be convertible to BigInt (ArrayBuffer, ArrayBufferView, BinaryData, BigInt, etc.)
    // sig MUST be an object containing two keys named r and s, which form the signature
    //   The r and s keys MUST be convertible to BigInt
    // returns a Promise that resolves with boolean true if the signature is valid and boolean false otherwise
    // TODO: allow sig to be a single buffer containing r || s (where || is concatenation)
    static verify(key, m, sig) {
        if (key[_handle] === undefined
            || _keyMaterial.get(key[_handle]) === undefined
            || _keyMaterial.get(key[_handle]).type !== "public")
        {
            throw new Error("key must be a DSA publicKey");
        }

        var keyInfo = _keyMaterial.get(key[_handle]);
        var y = keyInfo.key;
        var domInfo = _keyMaterial.get(keyInfo.domain);
        var hashFunc = domInfo.hash;
        var p = domInfo.p;
        var q = domInfo.q;
        var g = domInfo.g;
        var N = domInfo.N;
        var r = BigInt(sig.r);
        var s = BigInt(sig.s);
        var outlen, hashLen;

        if (keyInfo.usages.indexOf("verify") === -1) {
            throw new Error("key may not be used for verification");
        }

        var Hash = m => crypto.subtle.digest(hashFunc, m).then(d => new Uint8Array(d.buffer, 0, hashLen));

        return crypto.subtle.digest(hashFunc, new Uint8Array(1)).then(function (d) {
            outlen = d.byteLength;
            hashLen = Math.min(N, outlen) / 8;

            if (!r.greater(0) || !s.greater(0) || !r.lesser(q) || !s.lesser(q)) {
                return false;
            }

            // compute inverse of s mod q
            return (function Step3(i, j, y2, y1) {
                var dm = i.divmod(j);
                var y = y2.subtract(y1.multiply(dm.quotient));

                if (dm.remainder.greater(0)) {
                    return Step3(j, dm.remainder, y1, y);
                } else if (!j.isUnit()) {
                    throw new Error("Could not compute inverse of k");
                } else {
                    return y1.mod(q); // y2 mod a in spec, but we skipped over the part that set y2 = y1, and a = q
                }
            })(q, s, BigInt.zero, BigInt.one);
        }).then(function (si) {
            var w = si.mod(q);

            return Hash(m).then(function (z) {
                var u1 = BigInt(z).multiply(w).mod(q);
                var u2 = r.multiply(w).mod(q);
                var v = g.pow(u1).multiply(y.pow(u2)).mod(p).mod(q);

                return v.compare(r) === 0;
            });
        });
    }

    // returns a Promise that resolves with an object (in CryptoKeyPair form, not an instanceof CryptoKeyPair)
    // contains both public and private keys (in CryptoKey form, although neither are instanceof CryptoKey)
    // keygenParams MUST be an object with the following keys:
    //   name: "DSA"
    //   hash: A hash algorithm identifier, such as "SHA-256" or "SHA-512"
    //   modulusLength: bit length of the prime p (such as 2048 or 3072)
    //   divisorLength: bit length of the prime q (such as 224 or 256)
    // keygenParams SHOULD additionally contain the key "domain", to explicitly specify domain parameters.
    // The domain key if specified MUST contain an object with the following properties:
    //   modulus: the prime p as something convertible to BigInt
    //   divisor: the prime q as something convertible to BigInt
    //   generator: the number g as something convertible to BigInt
    // If domain parameters are given, modulusLength MUST match the bit length of modulus, divisorLength MUST match the
    // bit length of divisor, divisor MUST divide modulus - 1, and divisor raised to the generator power MUST be
    // congruent to 1 (mod modulus). The last two relations can be expressed with the following equations:
    // p - 1 = 0 (mod q)
    // q^g = 1 (mod p)
    // Finally, p and g MUST NOT be divisible by 2, 3, or 5. This is done as a quick way of ensuring that obvious
    // non-primes are not used for domain parameters in lieu of formal provable or probable primality tests.
    //
    // If the domain key is not specified, the domain parameters are generated for you and can be accessed in the
    // algorithms dictionary of the returned keys (as algorithms.domain). It is *highly* recommended that you specify
    // domain parameters, however, as generating them via js can take a very long time (e.g. minutes).
    //
    // extractable MAY be specified. If specified, it MUST be a boolean that describes whether or not the private key
    //   is extractable via exportKey(). If unspecified, the default value is true (e.g. private key is extractable)
    // keyUsages MAY be specified. If specified, it MUST be an array that MAY contain the following values:
    //   sign: If keyUsages contains "sign", then the privateKey may be used to sign messages via sign().
    //   verify: If keyUsages contains "verify", then the publicKey may be used to verify messages via verify().
    //   If specified, keyUsages MUST contain "sign" and SHOULD contain "verify". It MUST NOT contain any other values.
    //   If unspecified, keyUsages is the array ["sign", "verify"].
    static generateKey(keygenParams, extractable, keyUsages) {
        // check for all of the appropriate params
        if (keygenParams.name !== "DSA"
            || keygenParams.hash === undefined
            || keygenParams.modulusLength === undefined
            || keygenParams.divisorLength === undefined)
        {
            throw new Error("Invalid parameter dictionary");
        }

        if (keygenParams.modulusLength % 8 !== 0 || keygenParams.divisorLength % 8 !== 0) {
            throw new Error("Invalid modulusLength/divisorLength");
        }

        if (extractable === undefined) {
            extractable = true;
        }

        if (keyUsages === undefined) {
            keyUsages = ["sign", "verify"];
        } else if (keyUsages.indexOf("sign") === -1) {
            throw new Error("keyUsages must contain the value 'sign'");
        } else if (keyUsages.reduce((p, c) => p || (c !== "sign" && c !== "verify"), false)) {
            throw new Error("keyUsages contains an unexpected value");
        }

        var L = keygenParams.modulusLength;
        var N = keygenParams.divisorLength;
        var outlen, q, qseed, qgenCounter, p, p0, pseed, pgenCounter, iterations, oldCounter;
        var firstseed, g, domainParameterSeed, index;

        if (keygenParams.domain !== undefined) {
            // check for existing domain params
            if (keygenParams.domain.modulus === undefined
                || keygenParams.domain.divisor === undefined
                || keygenParams.domain.generator === undefined)
            {
                throw new Error("Invalid domain parameter dictionary");
            }

            return new Promise(function (resolve, reject) {
                p = BigInt(keygenParams.domain.modulus);
                q = BigInt(keygenParams.domain.divisor);
                g = BigInt(keygenParams.domain.generator);

                if (p.toBinaryData().buffer.byteLength * 8 != L || q.toBinaryData().buffer.byteLength * 8 != N) {
                    reject(new Error("modulus/divisor do not match modulusLength/divisorLength"));
                }

                if (!p.subtract(1).mod(q).isZero()) {
                    reject(new Error("modulus and divisor do not have the proper relation with each other"));
                }

                if (!g.modPow(q, p).isUnit()) {
                    reject(new Error("generator does not have proper relation with divisor and modulus"));
                }

                if (p.mod(2).isZero() || p.mod(3).isZero() || p.mod(5).isZero()) {
                    reject(new Error("modulus is not prime"));
                }

                if (q.mod(2).isZero() || q.mod(3).isZero() || q.mod(5).isZero()) {
                    reject(new Error("divisor is not prime"));
                }

                finish(resolve);
            });
        }

        function finish(resolve) {
            var c = crypto.getRandomValues(new Uint8Array((N + 64) / 8));
            var x = BigInt(c).mod(q.subtract(1)).add(1);
            var y = g.modPow(x, p);

            var pubSymb = Symbol("UniqueHandle");
            var privSymb = Symbol("UniqueHandle");
            var domSymb = Symbol("UniqueHandle");
            var publicKey = {
                type: "public",
                extractable: true,
                algorithm: {
                    name: "DSA",
                    modulusLength: keygenParams.modulusLength,
                    divisorLength: keygenParams.divisorLength,
                    hash: keygenParams.hash,
                    domain: {
                        modulus: p.toString(),
                        divisor: q.toString(),
                        generator: g.toString()
                    }
                },
                usages: keyUsages.indexOf("verify") !== -1 ? ["verify"] : []
            };
            publicKey[_handle] = pubSymb;
            Object.freeze(publicKey);
            Object.freeze(publicKey.algorithm);
            Object.freeze(publicKey.algorithm.domain);
            Object.freeze(publicKey.usages);
            var privateKey = {
                type: "private",
                extractable: Boolean(extractable),
                algorithm: {
                    name: "DSA",
                    modulusLength: keygenParams.modulusLength,
                    divisorLength: keygenParams.divisorLength,
                    hash: keygenParams.hash,
                    domain: {
                        modulus: p.toString(),
                        divisor: q.toString(),
                        generator: g.toString()
                    }
                },
                usages: ["sign"]
            };
            privateKey[_handle] = privSymb;
            Object.freeze(privateKey);
            Object.freeze(privateKey.algorithm);
            Object.freeze(privateKey.algorithm.domain);
            Object.freeze(privateKey.usages);
            _keyMaterial.set(privSymb, {
                type: "private",
                key: x,
                extractable: Boolean(extractable),
                usages: ["sign"],
                domain: domSymb
            });
            _keyMaterial.set(pubSymb, {
                type: "public",
                key: y,
                extractable: true,
                usages: keyUsages.indexOf("verify") !== -1 ? ["verify"] : [],
                domain: domSymb
            });
            _keyMaterial.set(domSymb, {
                p: p,
                q: q,
                g: g,
                L: L,
                N: N,
                hash: keygenParams.hash,
                firstseed: firstseed,
                pgen_seed: pseed,
                qgen_seed: qseed,
                domain_parameter_seed: domainParameterSeed,
                qgen_counter: qgenCounter,
                pgen_counter: pgenCounter,
                index: index
            });

            // resolve with the CryptoKeyPair
            var keyPair = {
                publicKey: publicKey,
                privateKey: privateKey
            };
            Object.freeze(keyPair);
            resolve(keyPair);
        }

        return new Promise(function (resolve, reject) {
            // generate the primes p and q
            firstseed = new Uint8Array(Math.ceil(keygenParams.divisorLength / 8));
            var Hash = m => crypto.subtle.digest(keygenParams.hash, m);

            do {
                firstseed = crypto.getRandomValues(firstseed);
            } while (firstseed[0] & (1 << 7) === 0);

            // we do not validate L and N here because there is no need to restrict them to the NIST recommended values
            Hash(new Uint8Array(1)).then(function (res) {
                outlen = res.byteLength * 8;

                if (outlen < keygenParams.divisorLength) {
                    reject(new Error("Hash function cannot have lower bit length than divisorLength."));
                }

                return Prime.ST(N, firstseed, keygenParams.hash);
            }).then(function (res) {
                q = res[0];
                qseed = res[1];
                qgenCounter = res[2];

                return Prime.ST(Math.ceil(L / 2 + 1), qseed, keygenParams.hash);
            }).then(function (res) {
                p0 = res[0];
                pseed = res[1];
                pgenCounter = res[2];
                iterations = Math.ceil(L / outlen) - 1;
                oldCounter = pgenCounter;

                return (function Step7(i, x) {
                    return Hash(BigInt(pseed).add(i).toBinaryData().buffer).then(function (d) {
                        x = x.add(BigInt(d).multiply(BigInt.two.pow(i * outlen)));

                        if (i < iterations) {
                            return Step7(i + 1, x);
                        } else {
                            return x;
                        }
                    });
                })(0, BigInt.zero);
            }).then(function (x) {
                pseed = BigInt(pseed).add(iterations).add(1).toBinaryData().buffer;
                x = pow2(L - 1).add(x.mod(pow2(L - 1)));
                var dm = x.divmod(BigInt.two.multiply(q).multiply(p0));
                var t = dm.quotient.add(dm.remainder.isZero() ? 0 : 1);

                return (function Step11(t) {
                    if (pgenCounter > 4 * L + oldCounter) {
                        reject(new Error("Could not find a prime with the given seed"));
                    }

                    if (BigInt.two.multiply(t).multiply(q).multiply(p0).add(1).greater(pow2(L))) {
                        let dm = pow2(L - 1).divmod(BigInt.two.multiply(q).multiply(p0));
                        t = dm.quotient.add(dm.remainder.isZero() ? 0 : 1);
                    }

                    var p = BigInt.two.multiply(t).multiply(q).multiply(p0).add(1);
                    pgenCounter++;

                    return (function Step15(i, a) {
                        return Hash(BigInt(pseed).add(i).toBinaryData().buffer).then(function (d) {
                            a = a.add(BigInt(d).multiply(BigInt.two.pow(i * outlen)));

                            if (i < iterations) {
                                return Step15(i + 1, a);
                            } else {
                                return a;
                            }
                        });
                    })(0, BigInt.zero).then(function (a) {
                        pseed = BigInt(pseed).add(iterations).add(1).toBinaryData().buffer;
                        a = BigInt.two.add(a.mod(p.subtract(3)));
                        var z = a.modPow(BigInt.two.multiply(t).multiply(q), p);

                        if (BigInt.gcd(z.subtract(1), p).isUnit() && z.modPow(p0, p).isUnit()) {
                            return p;
                        } else {
                            return Step11(t.add(1));
                        }
                    });
                })(t);
            }).then(function (p_) {
                p = p_;

                // domain_parameter_seed = firstseed || pseed || qseed according to A.2.3
                var domainParameterSeed = new Uint8Array(firstseed.byteLength + pseed.byteLength + qseed.byteLength);
                domainParameterSeed.set(firstseed, 0);
                domainParameterSeed.set(pseed, firstseed.byteLength);
                domainParameterSeed.set(qseed, firstseed.byteLength + pseed.byteLength);
                var index = new Uint8Array([1]);
                var encoder = new TextEncoder();
                var ggen = encoder.encode("ggen");
                var e = p.subtract(1).divide(q);
                var count = new DataView(new ArrayBuffer(2));
                count.setUint16(0, count.getUint16(0, false) + 1, false);
                var U = new Uint8Array(domainParameterSeed.byteLength + 7);
                U.set(domainParameterSeed, 0);
                U.set(ggen, domainParameterSeed.byteLength);
                U.set(index, domainParameterSeed.byteLength + 4);

                return (function Step6() {
                    if (count.getUint16(0, false) === 0) {
                        reject(new Error("Could not generate domain generator"));
                    }


                    U.set(new Uint8Array(count.buffer), domainParameterSeed.byteLength + 5);

                    return Hash(U).then(function (W) {
                        var g = BigInt(W).modPow(e, p);

                        if (g.lesser(2)) {
                            count.setUint16(0, count.getUint16(0, false) + 1, false);
                            return Step6();
                        } else {
                            return [g, domainParameterSeed, index];
                        }
                    });
                })();
            }).then(function (res) {
                g = res[0];
                domainParameterSeed = res[1];
                index = res[2];
                finish(resolve);
            });
        });
    }

    static importKey() {

    }

    // returns a Promise that resolves with the exported key in the specified format
    // format MUST be one of the following strings that denotes export format: "raw", "pkcs8", "spki", "jwk"
    // key MUST be a key object (public or private) returned from generateKey() or importKey() and must be extractable
    // if exporting a private key, the public key will be included in the exported value
    // TODO: At this time, only raw and jwk are supported. Add support for pkcs8 and spki (will need a DER encoder)
    static exportKey(format, key) {
        if (key[_handle] === undefined
            || _keyMaterial.get(key[_handle]) === undefined
            || !_keyMaterial.get(key[_handle]).extractable)
        {
            throw new Error("key must be an extractable DSA key");
        }

        if (["raw", "pkcs8", "spki", "jwk"].indexOf(format) === -1) {
            throw new Error("Invalid output format");
        } else if (["pkcs8", "spki"].indexOf(format) !== -1) {
            throw new Error("Unsupported output format");
        }

        return new Promise(function (resolve) {
            var k = _keyMaterial.get(key[_handle]),
                d = _keyMaterial.get(k.domain);

            // if raw, just give access to a copy of the Uint8Array buffer containing the keying material; simples
            // since domain parameters are available in the key objects already, this only contains the bytes
            // for the public or private key (whichever was passed)
            if (format === "raw") {
                resolve(k.key.toBinaryData().buffer);
            } else if (format === "jwk") {
                var obj = {
                    // DSA is not in the JWK spec, so we use a collision-resistant name (a UUID in this instance)
                    // for kty (as allowed by the spec), and then clarify with custom parameters that this
                    // is DSA. The use of a UUID for kty allows us to differentiate between our custom version of a
                    // DSA JWK and other custom implementations
                    kty: _uuidKty,
                    alg: getAlgUuid(d),
                    use: "sig",
                    key_ops: k.usages,
                    key_type: "DSA",
                    algorithm: getAlgName(d),
                    p: Base64.urlencode(d.p),
                    q: Base64.urlencode(d.q),
                    g: Base64.urlencode(d.g)
                };

                if (k.type === "public") {
                    obj.y = Base64.urlencode(k.key);
                } else {
                    obj.x = Base64.urlencode(k.key);
                }

                if (getAlgName(d) === "other") {
                    obj.hash = d.hash;
                    obj.L = d.L;
                    obj.N = d.N;
                }

                // if we have seed information, include it
                if (d.firstseed !== undefined) {
                    obj.firstseed = Base64.urlencode(d.firstseed);
                    obj.pgen_seed = Base64.urlencode(d.pgen_seed);
                    obj.qgen_seed = Base64.urlencode(d.qgen_seed);
                    obj.domain_parameter_seed = Base64.urlencode(d.domain_parameter_seed);
                    obj.qgen_counter = d.qgen_counter;
                    obj.pgen_counter = d.pgen_counter;
                    obj.index = d.index;
                }

                resolve(obj);
            }
        });
    }
}
//temp
DSA.h = _handle;
DSA.k = _keyMaterial;
return DSA;
});

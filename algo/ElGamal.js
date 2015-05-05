define(["../util/BigInt"], function (BigInt) {
"use strict";

// Implementation of the ElGamal encryption system
// http://caislab.kaist.ac.kr/lecture/2010/spring/cs548/basic/B02.pdf
// TODO: key generation, and have encrypt generate k if one was not specified
class ElGamal {
    // in the OpenPGP spec, the param order is p, g, k, y, m
    // the y below is y sub b in the pdf linked (aka public key of the recipient)
    // the choice of p and a are outside of the scope of this class
    // k is an ephemeral value and need not be tied to the sender's key
    static encrypt(p, a, k, y, m) {
        // return [c1, c2] where c1 = a^k mod p and c2 = m * y^k mod p
        // return each number as an undecorated Uint8Array in big endian format
        // (e.g. no two-octet length field as needed by OpenPGP MPI)
        return [
            BigInt(a).modPow(k, p).toBinaryData().buffer,
            BigInt(m).multiply(BigInt(y).modPow(k, p)).toBinaryData().buffer
        ];
    }

    // x is the recipient's private key, c1 and c2 are the result of encrypt, p is the prime
    static decrypt(p, x, c1, c2) {
        // return m where m = c2 / (c1^x mod p)
        // will be an undecorated Uint8Array in big endian format as described above in encrypt
        return BigInt(c2).divide(BigInt(c1).modPow(x, p)).toBinaryData().buffer;
    }
}

return ElGamal;
});

define(["../util/BigInt"], function (BigInt) {
"use strict";

var primes = {
    cache: {},
    get: function (n) {
        if (!primes.cache.hasOwnProperty(n)) {
            // compute 2^n - 1 easily by making a Uint8Array where every bit position up until n is 1
            var result = [],
                rem = n % 8;

            for (let i = 0; i < n - 8; i += 8) {
                result.push(255);
            }

            if (rem > 0) {
                result.unshift(0);

                for (let i = 0; i < rem; i++) {
                    result[0] |= (1 << i);
                }
            }

            primes.cache[n] = BigInt(new Uint8Array(result));
        }

        return primes.cache[n];
    }
};

class ShamirsSecretSharing {

    // secret should be a BinaryData, piecesNeeded and totalPieces should be ints
    // secret is meant to be a key for e.g. symmetric encryption as opposed to the message itself
    // secret cannot be larger than 512 bytes (4096 bits)
    // the prime argument can be undefined or boolean true (in which case a Mersenne prime is chosen),
    //   or you can supply your own prime number (as something convertible to a BigInt, such as BinaryData),
    //   or you can supply a falsey value to disable the mod prime behavior
    // returns an object containing two fields:
    //   prime: the prime number chosen as the modulus base as a BinaryData
    //   pieces: array of length totalPieces with each element being an object with two fields:
    //     x: js number containing the x value
    //     y: BinaryData containing the y value
    static split(secret, piecesNeeded, totalPieces, prime) {
        var secretLen = secret.byteLength,
            a = Array(piecesNeeded),
            pieces = [];

        if (!Number.isInteger(piecesNeeded) || !Number.isInteger(totalPieces)) {
            throw new Error("piecesNeeded and totalPieces must both be ints");
        }

        if (piecesNeeded < 2) {
            throw new Error("piecesNeeded cannot be less than 2");
        }

        if (totalPieces < piecesNeeded) {
            throw new Error("totalPieces cannot be less than piecesNeeded");
        }

        if (secretLen === 0) {
            throw new Error("secret is empty");
        }

        if (secretLen > 512) {
            throw new Error("secret must be no larger than 512 bytes");
        }

        a[0] = secret;

        for (let i = 1; i < piecesNeeded; i++) {
            a[i] = crypto.getRandomValues(new Uint8Array(secretLen));
        }

        var max = a.reduce((p, c) => BigInt.max(p, c)),
            p = ShamirsSecretSharing.getPrime(max);

        if (prime && prime !== true) {
            p = BigInt(prime);
        }

        for (let i = 1; i <= totalPieces; i++) {
            let res = BigInt.zero;

            for (let j = 0; j < a.length; j++) {
                res = res.add(BigInt(a[j]).multiply(BigInt(i).pow(j)));

                if (prime) {
                    res = res.mod(p);
                }
            }

            pieces.push({x: i, y: res.toBinaryData()});
        }

        if (!prime) {
            return {
                prime: false,
                pieces: pieces
            };
        }

        return {
            prime: p.toBinaryData(),
            pieces: pieces
        };
    }

    // prime should either be something convertable to a BigInt (e.g. BinaryData),
    //   or a falsey value to indicate no prime
    // pieces should be in the format returned by split()
    static combine(pieces, prime) {
        var result = BigInt.zero,
            fractions = [],
            lcm = BigInt.one;

        for (let j = 0; j < pieces.length; j++) {
            let num = BigInt.one,
                denom = BigInt.one;

            for (let m = 0; m < pieces.length; m++) {
                if (m === j) {
                    continue;
                }

                num = num.multiply(pieces[m].x).multiply(BigInt.minusOne);
                denom = denom.multiply(pieces[j].x - pieces[m].x);
            }

            let dm = num.multiply(pieces[j].y).divmod(denom);
            result = result.add(dm.quotient);

            if (prime) {
                result = result.mod(prime);
            }

            if (!dm.remainder.isZero()) {
                fractions.push({n: dm.remainder, d: denom.abs()});
                lcm = BigInt.lcm(lcm, denom.abs());
            }
        }

        var fresult = BigInt.zero;

        for (let i = 0; i < fractions.length; i++) {
            let scale = lcm.divide(fractions[i].d);

            fresult = fresult.add(fractions[i].n.multiply(scale));
        }

        result = result.add(fresult.divide(lcm));

        if (prime) {
            result = result.mod(prime);
        }

        try {
            return result.toBinaryData();
        } catch (e) {
            if (e.message === "Parameter 1 of BinaryData.fromHexString must be a hex string") {
                return false; // this usually means not enough pieces were given
            }

            throw e;
        }
    }

    // gets lowest Mersenne prime larger than num
    // num should be a BigInt or something convertable to one (such as BinaryData)
    static getPrime(num) {
        var available = [13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689];

        for (let i = 0; i < available.length; i++) {
            if (primes.get(available[i]).greater(num)) {
                return primes.get(available[i]);
            }
        }

        throw new Error("secret too large");
    }
}

return ShamirsSecretSharing;
});
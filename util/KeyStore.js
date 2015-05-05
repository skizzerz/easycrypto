define(function () {
"use strict";

// Key storage that stores keys in IndexedDB to persist them across sessions
// Keys are shared between every EasyCrypto instance on a given origin
// Note that right now we do not persist anything to IndexedDB, this makes initial development a bit easier
class KeyStore {
    constructor() {
        this.ephemeralStore = {};
    }

    // Retrieves a key of the given keyName with the capability to sign and verify data,
    // creating a new key with that name if it does not exist
    getSigningKey(keyName, options) {
        var keyPair = this.ephemeralStore["sign:" + keyName],
            self = this;

        if (keyPair === undefined) {
            let keygenParams = { name: options.algorithms.sign };

            switch (options.algorithms.sign) {
                case "RSA-PSS":
                    keygenParams.modulusLength = options.rsaModulusLength;
                    keygenParams.publicExponent = options.rsaLargeExponent ? _F4 : _F0;
                    keygenParams.hash = options.hash;
                    break;
                case "ECDSA":
                    keygenParams.namedCurve = options.ecNamedCurve;
                    break;
            }

            // as of right now, all keys are exportable
            // TODO: determine if this is the behavior we actually want
            return crypto.subtle.generateKey(keygenParams, true, ["sign", "verify"]).then(kp => {
                self.ephemeralStore["sign:" + keyName] = kp;
                return kp;
            });
        }

        return Promise.resolve(keyPair);
    }

    // Retrieves a key of the given keyName with the capability to encrypt and decrypt data,
    // creating a new key with that name if it does not exist
    getAsymmetricEncryptionKey(keyName) {

    }

    getSymmetricEncryptionKey(keyName, options) {
        var key = this.ephemeralStore["sEncrypt:" + keyName],
            self = this;

        if (key === undefined) {
            let keygenParams = { name: options.algorithms.sEncrypt };

            switch (options.algorithms.sEncrypt) {
                case "AES-CTR":
                case "AES-CBC":
                case "AES-CFB":
                case "AES-GCM":
                    keygenParams.length = options.aesLength;
                    break;
                default:
                    throw new Error(options.algorithms.sEncrypt + " is not a valid symmetric encryption algorithm");
            }

            // as of right now, all keys are exportable
            // TODO: determine if this is the behavior we actually want
            return crypto.subtle.generateKey(keygenParams, true, ["encrypt", "decrypt"]).then(k => {
                self.ephemeralStore["sEncrypt:" + keyName] = k;
                return k;
            });
        }

        return Promise.resolve(key);
    }
}

return KeyStore;
});
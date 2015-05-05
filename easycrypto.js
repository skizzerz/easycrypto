/**
 * EasyCrypto library for js
 *
 */

/* jshint undef:true, unused:true, curly:true, esnext:true */

// Use AMD for now, until browsers start supporting ES6 module syntax
define(
    ["./util/BinaryData", "./util/KeyStore", "./util/PublicKey", "./util/SecretKey", "./pgp/OpenPGP"],
    function (BinaryData, KeyStore, PublicKey, SecretKey, OpenPGP) {
"use strict";

// Contains our current library version
const _version = "0.2.1";

if (!crypto || !crypto.subtle || !crypto.getRandomValues) {
    // http://www.w3.org/TR/WebCryptoAPI
    // while there may be polyfills available, it is recommended that you do NOT use them,
    // as any pure-js implementation of the Web Cryptography API will have security risks
    throw new Error("EasyCrypto requires support for the Web Cryptography API");
}

// note that the existence of WebCrypto necessitates the existence of Promises and TypedArrays,
// so we don't need to explicitly check for those

if (!TextEncoder) {
    // http://www.w3.org/TR/encoding
    // polyfill available at https://github.com/inexorabletash/text-encoding
    throw new Error("EasyCrypto requires support for the Encoding specification");
}

if (!indexedDB) {
    // http://www.w3.org/TR/IndexedDB
    // polyfills will not work, as it is impossible to perform a pure-js implementation of structured clone,
    // which is required in order to store non-exportable CryptoKeys
    throw new Error("EasyCrypto requires support for IndexedDB");
}

// Contains the key store
var _keyStore = new KeyStore();

// contains the numbers 3 and 65537, for use as the RSA public exponent (65537 is default)
var _F0 = new Uint8Array([3]);
var _F4 = new Uint8Array([1, 0, 1]);

// contains salt lengths to use in the event we are salting signatures
var _saltLengths = {
    "SHA-1": 20,
    "SHA-256": 32,
    "SHA-512": 64
};

// means of holding semi-private options on a class
var _options = Symbol("options");

/*export default */class EasyCrypto {
    constructor(options) {
        this[_options] = {
            // if true, we specify a salt for use with RSA-PSS (length = hash size), if false the salt length is 0
            salt: true,
            // the underlying hash algorithm to use for most everything
            hash: "SHA-256",
            // the named curve to use for elliptical curve algorithms
            ecNamedCurve: "P-256",
            // the modulus length for RSA keys
            rsaModulusLength: 2048,
            // if true, the public exponent for RSA is 65537, if false it is 3
            rsaLargeExponent: true,
            // the length for AES keys
            aesLength: 256,
            // the length (in bits) for the counter in AES-CTR -- must be between 0 and 128, inclusive
            aesCounterLength: 32,
            // tag length (in bits) for AES-GCM -- allowed values are 128, 120, 112, 104, 96, 64, and 32
            aesGcmTagLength: 128,
            // length (in bytes) for the IV in AES-GCM -- max of 65536
            aesGcmIvLength: 16,
            // default key types for various algorithms, used to generate new keys
            algorithms: {
                sign: "RSA-PSS",
                aEncrypt: "RSA-OAEP",
                sEncrypt: "AES-CBC",
            }
        };

        if (typeof options == "object") {
            if ("salt" in options) {
                this[_options].salt = Boolean(options.salt);
            }
            if ("hash" in options) {
                this[_options].hash = options.hash.toString();
            }
            if ("ecNamedCurve" in options) {
                this[_options].ecNamedCurve = options.ecNamedCurve.toString();
            }
            if ("rsaModulusLength" in options) {
                this[_options].rsaModulusLength = Number(options.rsaModulusLength);
            }
            if ("rsaLargeExponent" in options) {
                this[_options].rsaLargeExponent = Boolean(options.rsaLargeExponent);
            }
            if ("aesLength" in options) {
                this[_options].aesLength = Number(options.aesLength);
            }
            if ("aesCounterLength" in options) {
                this[_options].aesCounterLength = Number(options.aesCounterLength);
            }
            if ("aesGcmTagLength" in options) {
                this[_options].aesGcmTagLength = Number(options.aesGcmTagLength);
            }
            if ("aesGcmIvLength" in options) {
                this[_options].aesGcmIvLength = Number(options.aesGcmIvLength);
            }
            if ("algorithms" in options && typeof options.algorithms == "object") {
                if ("sign" in options.algorithms) {
                    this[_options].algorithms.sign = options.algorithms.sign.toString();
                }
                if ("aEncrypt" in options.algorithms) {
                    this[_options].algorithms.aEncrypt = options.algorithms.aEncrypt.toString();
                }
                if ("sEncrypt" in options.algorithms) {
                    this[_options].algorithms.sEncrypt = options.algorithms.sEncrypt.toString();
                }
            }
        }
    }

    get version () { return _version; }

    // signs data with the private key of the given keyName
    // data: data to sign, copied on call so that modifications to the original do not impact the final result
    //       data can either be an ArrayBuffer (or any view into such a buffer, such as typed arrays), or any
    //       javascript object type, which will be converted internally to a JSON string before being signed
    // keyName: string name of key, uses "*" if not specified to indicate a generic signing key
    // returns a Promise that when resolved contains a SignedData object, which contains the signature, data, and key
    // and supports methods to export the data in common formats (such as OpenPGP)
    sign(data, keyName) {
        if (keyName === undefined) {
            keyName = "*";
        }

        keyName = keyName.toString();
        var dataCopy,
            self = this;

        if (data instanceof ArrayBuffer) {
            dataCopy = data.slice(0);
        } else if (ArrayBuffer.isView(data)) {
            dataCopy = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
        } else {
            // the sign method can only take in an ArrayBuffer or ArrayBufferView, however we were passed neither
            // to sign this data, we first convert it to a JSON string and then encode it to a UInt8Array
            let encoder = new TextEncoder();
            dataCopy = encoder.encode(JSON.stringify(data));
        }

        return _keyStore.getSigningKey(keyName, this[_options]).then(keyPair => {
            var signParams = { name: keyPair.privateKey.algorithm.name };

            switch (keyPair.privateKey.algorithm.name) {
                case "RSA-PSS":
                    signParams.saltLength = self[_options]["salt"]
                        ? _saltLengths[keyPair.privateKey.algorithm.hash.name]
                        : 0;
                    break;
                case "ECDSA":
                    signParams.hash = self[_options]["hash"];
                    break;
            }

            return crypto.subtle.sign(signParams, keyPair.privateKey, dataCopy).then(sig => {
                return {
                    signature: new BinaryData(sig),
                    data: new BinaryData(dataCopy),
                    key: new PublicKey(keyPair.publicKey, keyName, "signing")
                };
            });
        });
    }

    symmetricEncrypt(data, keyName) {
        if (keyName === undefined) {
            keyName = "*";
        }

        keyName = keyName.toString();
        var dataCopy,
            self = this;

        if (data instanceof ArrayBuffer) {
            dataCopy = data.slice(0);
        } else if (ArrayBuffer.isView(data)) {
            dataCopy = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
        } else {
            // the encrypt method can only take in an ArrayBuffer or ArrayBufferView, however we were passed neither
            // to sign this data, we first convert it to a JSON string and then encode it to a UInt8Array
            let encoder = new TextEncoder();
            dataCopy = encoder.encode(JSON.stringify(data));
        }

        return _keyStore.getSymmetricEncryptionKey(keyName, this[_options]).then(key => {
            var encryptParams = { name: key.algorithm.name },
                ivCopy;

            switch (key.algorithm.name) {
                case "AES-CBC":
                case "AES-CFB":
                    encryptParams.iv = crypto.getRandomValues(new Uint8Array(16));
                    ivCopy = encryptParams.iv.buffer.slice(0);
                    break;
                case "AES-CTR":
                    encryptParams.counter = crypto.getRandomValues(new Uint8Array(16));
                    encryptParams.length = self[_options].aesCounterLength;
                    // make a copy of the counter's stating state so we can return it later
                    ivCopy = encryptParams.counter.buffer.slice(0);
                    break;
                case "AES-GCM":
                    // symmetricEncrypt() does not support passing in additional data, use [TODO: function name] if
                    // you wish to do that
                    encryptParams.iv = crypto.getRandomValues(new Uint8Array(self[_options].aesGcmIvLength));
                    encryptParams.tagLength = self[_options].aesGcmTagLength;
                    ivCopy = encryptParams.iv.buffer.slice(0);
                    break;
                default:
                    throw new Error("Cannot use algorithm " + key.algorithm.name + " in EasyCrypto.symmetricEncrypt");
            }

            return crypto.subtle.encrypt(encryptParams, key, dataCopy).then(ct => {
                var tagLengthBytes = encryptParams.tagLength / 8,
                    haveTag = key.algorithm.name === "AES-GCM";

                if ("iv" in encryptParams) {
                    encryptParams.iv = ivCopy;
                } else if ("counter" in encryptParams) {
                    encryptParams.counter = ivCopy;
                }

                var retval = {
                    plaintext: new BinaryData(dataCopy),
                    key: new SecretKey(key, keyName, "encryption"),
                    params: encryptParams
                };
                
                if (haveTag) {
                    retval.ciphertext = new BinaryData(new Uint8Array(ct, 0, ct.byteLength - tagLengthBytes));
                    retval.additionalData = new BinaryData(new ArrayBuffer());
                    retval.tag = new BinaryData(new Uint8Array(ct, ct.byteLength - tagLengthBytes));
                } else {
                    retval.ciphertext = new BinaryData(ct);
                }
                
                return retval;
            });
        });
    }
}

// our export is EasyCrypto
return EasyCrypto;
});

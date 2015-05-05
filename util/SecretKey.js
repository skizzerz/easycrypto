define(["./Fingerprint"], function (Fingerprint) {
"use strict";

// wraps a secret (shared) key, providing a means of extracting information from it such as key fingerprint
// or text-based representations of the key
class SecretKey {
    constructor(key, keyName, keyClass) {
        this.key = key;
        this.keyName = keyName;
        this.keyClass = keyClass;
        this.fingerprint = new Fingerprint(key, "MD5");
        this.fingerprintSHA1 = new Fingerprint(key, "SHA-1");
        this.fingerprintSHA256 = new Fingerprint(key, "SHA-256");
    }
}

return SecretKey;
});

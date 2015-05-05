define(["../algo/md5"], function (md5) {
"use strict";

class Fingerprint {
    constructor(key, algo) {
        var self = this,
            format = "";

        if (key.type === "public") {
            format = "spki";
        } else if (key.type === "secret") {
            format = "raw";
        }

        this.bytes = null;
        this.string = null;
        this.promise = crypto.subtle.exportKey(format, key).then(data => {
            if (algo == "MD5") {
                // the Web Cryptography API does not implement MD5 so we need to use our own implementation
                return md5(data);
            } else {
                return crypto.subtle.digest(algo, data);
            }
        }).then(data => {
            var hex = [];

            self.bytes = new Uint8Array(data);

            for (let b of self.bytes) {
                hex.push(("0" + b.toString(16)).slice(-2));
            }

            self.string = hex.join(":");
            return data;
        });
    }

    toString() { return this.string; }
}

return Fingerprint;
});

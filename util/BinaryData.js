define(["./Base64"], function (Base64) {
"use strict";

// easily work with and export binary data to readable formats
class BinaryData {
    // buffer should be an ArrayBuffer or ArrayBufferView containing the data
    constructor(buffer) {
        if (ArrayBuffer.isView(buffer)) {
            this.buffer = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        } else {
            this.buffer = new Uint8Array(buffer);
        }
    }

    toString(encoding) {
        encoding = encoding || "hex";

        if (encoding.toLowerCase() == "hex") {
            return this.toHexString();
        } else if (encoding.toLowerCase() == "base64") {
            return this.toBase64String();
        }

        var decoder = new TextDecoder(encoding);
        return decoder.decode(this.buffer);
    }

    get byteLength() { return this.buffer.byteLength; }

    toHexString() {
        var hex = [];

        for (let b of this.buffer) {
            hex.push(("0" + b.toString(16)).slice(-2));
        }

        return hex.join("");
    }

    // if hex does not specify a full byte, it is zero-padded to the left
    // this is case-insensitive, however an error will be thrown if the string contains non hex digits
    static fromHexString(hex) {
        hex = hex.replace(/\s/g, '');

        if (hex === "") {
            return new BinaryData(new ArrayBuffer());
        }

        if (!/^[0-9a-f]+$/i.test(hex)) {
            throw new Error("Parameter 1 of BinaryData.fromHexString must be a hex string");
        }

        if (hex.length / 2 != Math.ceil(hex.length / 2)) {
            hex = "0" + hex;
        }

        var buffer = new Uint8Array(hex.length / 2);

        for (let i = 0; i < hex.length; i += 2) {
            buffer[i / 2] = parseInt(hex.substr(i, 2), 16);
        }

        return new BinaryData(buffer);
    }

    toBase64String() {
        return Base64.encode(this.buffer, true);
    }

    static fromBase64String(string) {
        return new BinaryData(Base64.decode(string));
    }
}

return BinaryData;
});
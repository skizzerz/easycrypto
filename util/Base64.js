define(function () {
"use strict";

var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var charmap = {};

for (let i = 0; i < charset.length; i++) {
    charmap[charset[i]] = i;
}

charmap["="] = 0;

// RFC 4880 (OpenPGP Message Format), Section 6.1
function crc24(bytes) {
    var crc = 0xb704ce;

    for (let i = 0; i < bytes.length; i++) {
        crc ^= bytes[i] << 16;
        for (let j = 0; j < 8; j++) {
            crc <<= 1;
            if (crc & 0x1000000) {
                crc ^= 0x1864cfb;
            }
        }
    }

    return new Uint8Array([(crc & 0xff0000) >>> 16, (crc & 0xff00) >>> 8, crc & 0xff]);
}

class Base64 {
    // encodes data into Base64
    // data can be either a utf-8 string or ArrayBuffer/ArrayBufferView
    // pad should be true if we should pad the string with = (default), or false if we should not pad
    // returns a string of the encoded data
    static encode(data, pad) {
        var bytes, length, string = "", pad3 = false, pad4 = false, padchar = "";

        if (pad === undefined) {
            pad = true;
        }

        if (pad) {
            padchar = "=";
        }

        if (data instanceof ArrayBuffer) {
            bytes = new Uint8Array(data);
        } else if (ArrayBuffer.isView(data)) {
            bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        } else {
            let encoder = new TextEncoder();
            bytes = encoder.encode(data);
        }

        length = bytes.length;

        for (let i = 0; i < length; i += 3) {
            let bitstream = bytes[i] << 16;

            if (i + 1 < length) {
                bitstream |= bytes[i + 1] << 8;

                if (i + 2 < length) {
                    bitstream |= bytes[i + 2];
                } else {
                    pad4 = true;
                }
            } else {
                pad3 = pad4 = true;
            }

            let n1 = (bitstream & (63 << 18)) >>> 18,
                n2 = (bitstream & (63 << 12)) >>> 12,
                n3 = (bitstream & (63 << 6)) >>> 6,
                n4 = (bitstream & 63);

            string += charset[n1] + charset[n2] + (pad3 ? padchar : charset[n3]) + (pad4 ? padchar : charset[n4]);
        }

        return string;
    }

    // decodes base64 data into a Uint8Array
    // string should be the base64 string (padding optional)
    static decode(string) {
        string = string.replace(/\s/g, "");

        if (string === "") {
            return new Uint8Array();
        }

        if (!/^[A-Za-z0-9+/]+=?=?$/.test(string)) {
            throw new Error("Parameter 1 of Base64.decode must be a base-64 string");
        } else if (string.length % 4 !== 0 && string.slice(-1) === "=") {
            throw new Error("Parameter 1 of Base64.decode must be a base-64 string");
        }

        // gets length in bits of the data
        var bitlength = string.length * 6;

        if (string.slice(-2) === "==") {
            bitlength -= 12;
        } else if (string.slice(-1) === "=") {
            bitlength -= 6;
        }

        var buffer = new Uint8Array(Math.floor(bitlength / 8));

        for (let i = 0; i < string.length; i += 4) {
            let parts = string.substr(i, 4).split(""),
                offset = i * 3 / 4;
            buffer[offset] = (charmap[parts[0]] << 2) | (charmap[parts[1]] >>> 4);

            if (parts[2] !== "=" && parts[2] !== undefined) {
                buffer[offset + 1] = ((charmap[parts[1]] & 15) << 4) | (charmap[parts[2]] >>> 2);

                if (parts[3] !== "=" && parts[3] !== undefined) {
                    buffer[offset + 2] = ((charmap[parts[2]] & 3) << 6) | charmap[parts[3]];
                }
            }
        }

        return buffer;
    }

    // encodes data into a Base64url format (using -_ instead of +/, and percent-encoding the padding = character)
    // data and pad are the same as Base64.encode, as is the return type
    static urlencode(data, pad) {
        return encodeURIComponent(Base64.encode(data, pad).replace(/\+/g, "-").replace(/\//g, "_"));
    }

    // decodes a string from a Base64url format
    static urldecode(string) {
        return Base64.decode(decodeURIComponent(string).replace(/-/g, "+").replace(/_/g, "/"));
    }

    // encodes data into Radix64 format specified by the OpenPGP spec. Line breaks are inserted every 76 characters
    // and a CRC-24 checksum is appended to the end. If title and headers are specified, this additionally ASCII armors
    // the result before returning it as a string. If title and headers are not specified, this returns an array with
    // the first element being the encoded string and the second element being the encoded checksum with leading "=".
    // data MUST be a Uint8Array, title is a string containing the armor header (without the BEGIN), e.g.
    // "PGP MESSAGE" or "PGP SIGNATURE", headers is an object containing string keys of the header keys and either
    // string or array of string values of header content. If an array of strings is given, the header will be repeated
    // once for each item in the array (one per line). The header values may not contain newlines, use the array
    // syntax if you wish to have a multiline header (such as a comment). Title and header keys are not verified, but
    // should also not contain any newlines.
    static radixencode(data, title, headers) {
        var armor, encoded, checksum;

        if (title !== undefined) {
            armor = "-----BEGIN " + title + "-----\r\n";

            if (headers !== undefined) {
                for (let k of Object.keys(headers)) {
                    if (!Array.isArray(headers[k])) {
                        headers[k] = [headers[k]];
                    }

                    for (let v of headers[k]) {
                        if (v.indexOf("\r") !== -1 && v.indexOf("\n") !== -1) {
                            // TODO: may want to convert these into new array values instead of throwing, but lazy
                            throw new Error("Header values may not contain newlines");
                        }

                        armor += k + ": " + v + "\r\n";
                    }
                }
            }

            armor += "\r\n";
        }

        encoded = Base64.encode(data, true);
        checksum = "=" + Base64.encode(crc24(data), false);

        if (title !== undefined) {
            for (let i = 0; i < encoded.length; i += 76) {
                armor += encoded.substr(i, 76) + "\r\n";
            }

            armor += checksum + "\r\n-----END " + title + "-----";
            return armor;
        } else {
            return [encoded, checksum];
        }
    }

    // this has two overloads:
    // 1. ArmorData radixdecode(String armorstring)
    // 2. Uint8Array radixdecode(String string, String checksum)
    // The first overload is used to decode a full ascii-armored block, including the header and tail. A string should
    // be passed in as armorstring. If the checksum parameter is omitted, this overload is used.
    // The second overload is used to decode just the data along with its associated checksum. Both should be strings,
    // and the checksum may start with a leading "=". If the checksum parameter is specified, this overload is used.
    // In either overload, if the checksum (either obtained from armorstring or passed into checksum) is invalid, an
    // error is thrown.
    // In the first overload, the ArmorData structure is defined as an Object with the following keys:
    //   title: the title derived from the ascii armor, minus the BEGIN (e.g. "PGP MESSAGE" or "PGP SIGNATURE")
    //   headers: an object with keys containing the header names, and values being an array of header values.
    //            The array will have one item per instance of the header appearing. No checking is done to
    //            validate that keys do not override prototype properties, do not call any methods directly on
    //            this object.
    //   data: the Uint8Array containing the decoded data.
    static radixdecode(string, checksum) {
        if (checksum !== undefined) {
            let data = Base64.decode(string);
            let p = Base64.decode(checksum.replace(/^=/, ""));
            let c = crc24(data);

            if (p.length !== 3) {
                throw new Error("Invalid checksum");
            }

            let providedChecksum = (p[0] << 16) | (p[1] << 8) | p[2];
            let computedChecksum = (c[0] << 16) | (c[1] << 8) | c[2];

            if (providedChecksum !== computedChecksum) {
                throw new Error("Invalid checksum");
            }

            return data;
        } else {
            let lines = string.replace(/\r\n/g, "\n").split("\n");
            let headers = {};

            // trim leading/trailing newlines
            while (lines[0] === "") {
                lines.shift();
            }

            while (lines[lines.length] === "") {
                lines.pop();
            }

            let begin = lines.shift().match(/^-----BEGIN (.*)-----$/); // title is begin[1]
            let end = lines.pop().match(/^-----END (.*)-----$/);

            if (begin === null || end === null || begin[1] !== end[1]) {
                throw new Error("Invalid ascii armored string");
            }

            while(lines.length > 0) {
                let line = lines.shift();

                if (line.replace(/\s/g, "") === "") {
                    break; // blank line found, done with headers
                }

                let bits = line.split(": ");

                if (bits.length < 2) {
                    // improper header, per spec treat this as corrupted ascii armor and reject
                    throw new Error("Invalid ascii armored string");
                }

                let key = bits.shift();

                if (!Object.hasOwnProperty(headers, key)) {
                    headers[key] = [];
                }

                headers[key].push(bits.join(": "));

                if (["Version", "Comment", "MessageID", "Hash", "Charset"].indexOf(key) === -1) {
                    console.log("Unknown OpenPGP header key: " + key);
                }
            }

            // remain[0] is our base64-encoded data (without padding), remain[1] is our checksum
            let remain = lines.join("").replace(/\s/g, "").split(/=+/);

            if (remain.length !== 2) {
                throw new Error("Invalid ascii armored string");
            }

            try {
                let data = Base64.decode(remain[0]);
                let p = Base64.decode(remain[1]);
                let c = crc24(data);

                if (p.length !== 3) {
                    throw new Error("Invalid ascii armored string");
                }

                let providedChecksum = (p[0] << 16) | (p[1] << 8) | p[2];
                let computedChecksum = (c[0] << 16) | (c[1] << 8) | c[2];

                if (providedChecksum !== computedChecksum) {
                    throw new Error("Invalid ascii armored string");
                }

                return {
                    title: begin[1],
                    headers: headers,
                    data: data
                };
            } catch (e) {
                throw new Error("Invalid ascii armored string");
            }
        }
    }
}

return Base64;
});

define(
    ["./util", "../util/BinaryData", "../vendor/pako"],
    function (util, BinaryData, pako) {
"use strict";

class Packet {
    constructor(offset) {
        this.offset = offset; // offset of packet into array buffer
        this.length = 0; // length of packet, including header
    }

    // data is an ArrayBuffer, offset is a byte offset into said buffer telling us where to start parsing
    // returns a packet object with info, including byte offset/length so we know where to look for the next packet
    // this does not perform any decryption/verification/decompression on the packet
    static decode(data, offset) {
        var packet = new Packet(offset),
            view = new DataView(data, offset);
        // 4.2 decode header
        var header = view.getUint8(0);
        if (!(header & 0x80)) {
            throw new Error("Unexpected data when parsing OpenPGP packet");
        }
        if (header & 0x40) {
            // new packet format
            packet.tag = header & 0x3f;
            let d = util.getData(data, offset + 1);
            view = d[1];
            packet.length = view.byteLength + d[0];
        } else {
            // old packet format
            packet.tag = (header & 0x3c) >>> 2;
            packet.length = header & 0x03; // will be replaced by actual byte length in a bit
            if (packet.length === 0) {
                packet.length = view.getUint8(1);
                view = new DataView(data, offset + 2, packet.length);
                packet.length += 2;
            } else if (packet.length === 1) {
                packet.length = view.getUint16(1, false);
                view = new DataView(data, offset + 3, packet.length);
                packet.length += 3;
            } else if (packet.length === 2) {
                packet.length = view.getUint32(1, false);
                view = new DataView(data, offset + 5, packet.length);
                packet.length += 5;
            } else if (packet.length === 3) {
                // indeterminate length, which for us means until the end of the ArrayBuffer
                packet.length = view.byteLength;
                view = new DataView(data, offset + 1);
            }
        }
        // parse data based on tag
        switch (packet.tag) {
            case Packet.RESERVED: // Reserved, cannot be used
                throw new Error("Unexpected data when parsing OpenPGP packet");
            case Packet.PUBLIC_SESSION_KEY: // Public-Key Encrypted Session Key
                {
                    let version = view.getUint8(0);
                    if (version !== 3) {
                        throw new Error("Unexpected data when parsing OpenPGP packet");
                    }
                    packet.keyId = new BinaryData(new DataView(view.buffer, view.byteOffset + 1, 8)).toHexString();
                    packet.keyAlgo = view.getUint8(9);
                    packet.encryptedKey = new DataView(view.buffer, view.byteOffset + 10, view.byteLength - 10);
                }
                break;
            case Packet.SIGNATURE: // Signature
                {
                    let version = view.getUint8(0);
                    if (version === 3) {

                    } else if (version === 4) {

                    } else {
                        throw new Error("Unexpected data when parsing OpenPGP packet");
                    }
                    // TODO: Finish, section 5.2 (is gigantic, probably split into its own function)
                }
                break;
            case Packet.SYMMETRIC_SESSION_KEY: // Symmetric-Key Encrypted Session Key

                break;
            case Packet.ONE_PASS_SIGNATURE: // One-Pass Signature
                break;
            case Packet.SECRET_KEY: // Secret-Key
                break;
            case Packet.PUBLIC_KEY: // Public-Key
                break;
            case Packet.SECRET_SUBKEY: // Secret-Subkey
                break;
            case Packet.COMPRESSED: // Compressed Data
                break;
            case Packet.SYMMETRIC_DATA: // Symmetrically Encrypted Data
                break;
            case Packet.MARKER: // Marker
                break;
            case Packet.LITERAL_DATA: // Literal Data
                break;
            case Packet.TRUST: // Trust
                break;
            case Packet.USER_ID: // User ID
                break;
            case Packet.PUBLIC_SUBKEY: // Public-Subkey
                break;
            case Packet.USER_ATTRIBUTE: // User Attribute
                break;
            case Packet.SIP_DATA: // Symmetrically Encrypted and Integrity Protected Data
                break;
            case Packet.MDC: // Modification Detection Code
                break;
            default:
                throw new Error("Unexpected data when parsing OpenPGP packet");
        }
    }
};
Packet.RESERVED = 0;
Packet.PUBLIC_SESSION_KEY = 1;
Packet.SIGNATURE = 2;
Packet.SYMMETRIC_SESSION_KEY = 3;
Packet.ONE_PASS_SIGNATURE = 4;
Packet.SECRET_KEY = 5;
Packet.PUBLIC_KEY = 6;
Packet.SECRET_SUBKEY = 7;
Packet.COMPRESSED = 8;
Packet.SYMMETRIC_DATA = 9;
Packet.MARKER = 10;
Packet.LITERAL_DATA = 11;
Packet.TRUST = 12;
Packet.USER_ID = 13;
Packet.PUBLIC_SUBKEY = 14;
Packet.USER_ATTRIBUTE = 17;
Packet.SIP_DATA = 18;
Packet.MDC = 19;

return Packet;
});
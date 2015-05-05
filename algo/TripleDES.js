define(function () {
"use strict";

// implementation of the TDEA (TripleDES/DES-EDE) symmetric encryption algorithm
// this implementation is used for the OpenPGP implementation to decrypt messages generated with this legacy algorithm,
// message should be an ArrayBuffer or ArrayBufferView
// key should be an ArrayBuffer or ArrayBufferView, the parity bit is NOT checked or validated
// mode must be "ECB" or "CFB-8"
// iv should be an ArrayBuffer or ArrayBufferView (undefined if mode = "ECB")
// this function should NEVER be exposed to an outside scope, either directly or indirectly
class TripleDES {
    static encrypt(m, key, mode, iv) {
        if (ArrayBuffer.isView(m)) {
            m = new Uint8Array(m.buffer, m.byteOffset, m.byteLength);
        } else {
            m = new Uint8Array(m);
        }

        if (ArrayBuffer.isView(key)) {
            key = new Uint8Array(key.buffer, key.byteOffset, key.byteLength);
        } else {
            key = new Uint8Array(key);
        }

        if (ArrayBuffer.isView(iv)) {
            iv = new Uint8Array(iv.buffer, iv.byteOffset, iv.byteLength);
        } else {
            iv = new Uint8Array(iv);
        }

        if (key.byteLength !== 24) {
            throw new Error("Incorrect Key Size");
        }

        if (mode !== "ECB" && iv.byteLength !== 8) {
            throw new Error("Incorrect IV Size");
        }

        var encrypted = m.buffer.slice(m.byteOffset, m.byteOffset + m.byteLength),
            eview = new Uint8Array(encrypted),
            key1 = new Uint8Array(key.buffer, key.byteOffset, 8),
            key2 = new Uint8Array(key.buffer, key.byteOffset + 8, 8),
            key3 = new Uint8Array(key.buffer, key.byteOffset + 16);

        if (mode === "CFB-8") {
            let block = new Uint8Array(iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength));
            for (let offset = 0; offset < m.byteLength; offset += 8) {
                block = TripleDES.F(TripleDES.I(TripleDES.F(block, key1), key2), key3);
                let j = 0;
                if (offset + 8 >= m.byteLength) {
                    j = 8 - (m.byteLength - offset);
                }
                for (let i = 0; i < 8; i++) {
                    if (offset + i >= m.byteLength) {
                        break;
                    }
                    eview[offset + i] = m[offset + i] ^ block[i + j];
                    block[i] = eview[offset + i];
                }
            }

            return eview;
        } else if (mode === "ECB") {
            for (let offset = 0; offset < m.byteLength; offset += 8) {
                let block = new Uint8Array(m.buffer, m.byteOffset + offset, 8);
                block = TripleDES.F(TripleDES.I(TripleDES.F(block, key1), key2), key3);
                for (let i = 0; i < 8; i++) {
                    eview[offset + i] = block[i];
                }
            }

            return eview;
        }

        throw new Error("Unsupported Mode");
    }

    static decrypt(m, key, mode, iv) {
        if (ArrayBuffer.isView(m)) {
            m = new Uint8Array(m.buffer, m.byteOffset, m.byteLength);
        } else {
            m = new Uint8Array(m);
        }

        if (ArrayBuffer.isView(key)) {
            key = new Uint8Array(key.buffer, key.byteOffset, key.byteLength);
        } else {
            key = new Uint8Array(key);
        }

        if (ArrayBuffer.isView(iv)) {
            iv = new Uint8Array(iv.buffer, iv.byteOffset, iv.byteLength);
        } else {
            iv = new Uint8Array(iv);
        }

        if (key.byteLength !== 24) {
            throw new Error("Incorrect Key Size");
        }

        if (mode !== "ECB" && iv.byteLength !== 8) {
            throw new Error("Incorrect IV Size");
        }

        var decrypted = m.buffer.slice(m.byteOffset, m.byteOffset + m.byteLength),
            dview = new Uint8Array(decrypted),
            key1 = new Uint8Array(key.buffer, key.byteOffset, 8),
            key2 = new Uint8Array(key.buffer, key.byteOffset + 8, 8),
            key3 = new Uint8Array(key.buffer, key.byteOffset + 16);

        if (mode === "CFB-8") {
            let block = new Uint8Array(iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength));
            for (let offset = 0; offset < m.byteLength; offset += 8) {
                block = TripleDES.F(TripleDES.I(TripleDES.F(block, key1), key2), key3);
                let j = 0;
                if (offset + 8 >= m.byteLength) {
                    j = 8 - (m.byteLength - offset);
                }
                for (let i = 0; i < 8; i++) {
                    if (offset + i >= m.byteLength) {
                        break;
                    }
                    dview[offset + i] = m[offset + i] ^ block[i + j];
                    block[i] = m[offset + i];
                }
            }

            return dview;
        } else if (mode === "ECB") {
            for (let offset = 0; offset < m.byteLength; offset += 8) {
                let block = new Uint8Array(m.buffer, m.byteOffset + offset, 8);
                block = TripleDES.I(TripleDES.F(TripleDES.I(block, key3), key2), key1);
                for (let i = 0; i < 8; i++) {
                    dview[offset + i] = block[i];
                }
            }

            return dview;
        }

        throw new Error("Unsupported Mode");
    }

    // for internal use only, do not call from outside of the class
    static F(data, key) {
        data = TripleDES.IP(data);
        for (let i = 1; i <= 16; i++) {
            let K = TripleDES.KS(i, key),
                L = new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + 4)),
                R = new Uint8Array(data.buffer.slice(data.byteOffset + 4, data.byteOffset + 8));
            for (let j = 0; j < 4; j++) {
                data[j] = R[j];
            }

            R = TripleDES.f(R, K);

            for (let j = 0; j < 4; j++) {
                data[j + 4] = L[j] ^ R[j];
            }
        }

        let temp = new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + 4));
        for (let i = 0; i < 4; i++) {
            data[i] = data[i + 4];
            data[i + 4] = temp[i];
        }

        return TripleDES.IPI(data);
    }

    static I(data, key) {
        data = TripleDES.IP(data);

        let temp = new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + 4));
        for (let i = 0; i < 4; i++) {
            data[i] = data[i + 4];
            data[i + 4] = temp[i];
        }

        for (let i = 16; i >= 1; i--) {
            let K = TripleDES.KS(i, key),
                LP = new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + 4)),
                RP = new Uint8Array(data.buffer.slice(data.byteOffset + 4, data.byteOffset + 8));

            for (let j = 0; j < 4; j++) {
                data[j + 4] = LP[j];
            }

            LP = TripleDES.f(LP, K);

            for (let j = 0; j < 4; j++) {
                data[j] = RP[j] ^ LP[j];
            }
        }

        return TripleDES.IPI(data);
    }

    static p(d, a) {
        var b = new Uint8Array(new ArrayBuffer(a.length / 8));
        for (let i = 0; i < a.length / 8; i++) {
            b[i] = 0;
            for (let j = 0; j < 8; j++) {
                b[i] |= ((d[Math.floor((a[8 * i + j] - 1) / 8)] >>> (7 - ((a[8 * i + j] - 1) % 8))) & 1) << (7 - j);
            }
        }
        return b;
    }

    static IP(data) {
        return TripleDES.p(data, [58, 50, 42, 34, 26, 18, 10, 2,
                                  60, 52, 44, 36, 28, 20, 12, 4,
                                  62, 54, 46, 38, 30, 22, 14, 6,
                                  64, 56, 48, 40, 32, 24, 16, 8,
                                  57, 49, 41, 33, 25, 17,  9, 1,
                                  59, 51, 43, 35, 27, 19, 11, 3,
                                  61, 53, 45, 37, 29, 21, 13, 5,
                                  63, 55, 47, 39, 31, 23, 15, 7]);
    }

    static IPI(data) { // inverse of IP
        return TripleDES.p(data, [40, 8, 48, 16, 56, 24, 64, 32,
                                  39, 7, 47, 15, 55, 23, 63, 31,
                                  38, 6, 46, 14, 54, 22, 62, 30,
                                  37, 5, 45, 13, 53, 21, 61, 29,
                                  36, 4, 44, 12, 52, 20, 60, 28,
                                  35, 3, 43, 11, 51, 19, 59, 27,
                                  34, 2, 42, 10, 50, 18, 58, 26,
                                  33, 1, 41,  9, 49, 17, 57, 25]);
    }

    static f(R, K) {
        R = TripleDES.E(R);
        for (let i = 0; i < 6; i++) {
            R[i] = K[i] ^ R[i];
        }
        let L = new Uint8Array(4);
        L[0] = (TripleDES.S1(R[0] >>> 2) << 4) | TripleDES.S2(((R[0] & 0x03) << 4) | ((R[1] & 0xf0) >>> 4));
        L[1] = (TripleDES.S3(((R[1] & 0x0f) << 2) | ((R[2] & 0xc0) >>> 6)) << 4) | TripleDES.S4(R[2] & 0x3f);
        L[2] = (TripleDES.S5(R[3] >>> 2) << 4) | TripleDES.S6(((R[3] & 0x03) << 4) | ((R[4] & 0xf0) >>> 4));
        L[3] = (TripleDES.S7(((R[4] & 0x0f) << 2) | ((R[5] & 0xc0) >>> 6)) << 4) | TripleDES.S8(R[5] & 0x3f);
        return TripleDES.P(L);
    }

    static E(R) {
        return TripleDES.p(R, [32,  1,  2,  3,  4,  5,
                                4,  5,  6,  7,  8,  9,
                                8,  9, 10, 11, 12, 13,
                               12, 13, 14, 15, 16, 17,
                               16, 17, 18, 19, 20, 21,
                               20, 21, 22, 23, 24, 25,
                               24, 25, 26, 27, 28, 29,
                               28, 29, 30, 31, 32,  1]);
    }

    static P(L) {
        return TripleDES.p(L, [16,  7, 20, 21,
                               29, 12, 28, 17,
                                1, 15, 23, 26,
                                5, 18, 31, 10,
                                2,  8, 24, 14,
                               32, 27,  3,  9,
                               19, 13, 30,  6,
                               22, 11,  4, 25]);
    }

    static S1(B) {
        return [[14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,  7],
                [ 0, 15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,  8],
                [ 4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,  0],
                [15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13]]
               [((B & 0x20) >>> 4) | (B & 0x01)][(B & 0x1e) >>> 1];
    }

    static S2(B) {
        return [[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12, 0,  5, 10],
                [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6, 9, 11,  5],
                [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9, 3,  2, 15],
                [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0, 5, 14,  9]]
               [((B & 0x20) >>> 4) | (B & 0x01)][(B & 0x1e) >>> 1];
    }

    static S3(B) {
        return [[10,  0,  9, 14, 6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
                [13,  7,  0,  9, 3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
                [13,  6,  4,  9, 8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
                [ 1, 10, 13,  0, 6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]]
               [((B & 0x20) >>> 4) | (B & 0x01)][(B & 0x1e) >>> 1];
    }

    static S4(B) {
        return [[ 7, 13, 14, 3,  0,  6,  9, 10,  1, 2, 8,  5, 11, 12,  4, 15],
                [13,  8, 11, 5,  6, 15,  0,  3,  4, 7, 2, 12,  1, 10, 14,  9],
                [10,  6,  9, 0, 12, 11,  7, 13, 15, 1, 3, 14,  5,  2,  8,  4],
                [ 3, 15,  0, 6, 10,  1, 13,  8,  9, 4, 5, 11, 12,  7,  2, 14]]
               [((B & 0x20) >>> 4) | (B & 0x01)][(B & 0x1e) >>> 1];
    }

    static S5(B) {
        return [[ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13, 0, 14,  9],
                [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3, 9,  8,  6],
                [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6, 3,  0, 14],
                [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10, 4,  5,  3]]
               [((B & 0x20) >>> 4) | (B & 0x01)][(B & 0x1e) >>> 1];
    }

    static S6(B) {
        return [[12,  1, 10, 15, 9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
                [10, 15,  4,  2, 7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
                [ 9, 14, 15,  5, 2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
                [ 4,  3,  2, 12, 9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]]
               [((B & 0x20) >>> 4) | (B & 0x01)][(B & 0x1e) >>> 1];
    }

    static S7(B) {
        return [[ 4, 11,  2, 14, 15, 0,  8, 13,  3, 12, 9,  7,  5, 10, 6,  1],
                [13,  0, 11,  7,  4, 9,  1, 10, 14,  3, 5, 12,  2, 15, 8,  6],
                [ 1,  4, 11, 13, 12, 3,  7, 14, 10, 15, 6,  8,  0,  5, 9,  2],
                [ 6, 11, 13,  8,  1, 4, 10,  7,  9,  5, 0, 15, 14,  2, 3, 12]]
               [((B & 0x20) >>> 4) | (B & 0x01)][(B & 0x1e) >>> 1];
    }

    static S8(B) {
        return [[13,  2,  8, 4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
                [ 1, 15, 13, 8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
                [ 7, 11,  4, 1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
                [ 2,  1, 14, 7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]]
               [((B & 0x20) >>> 4) | (B & 0x01)][(B & 0x1e) >>> 1];
    }

    static KS(i, key) {
        var CD = new DataView(TripleDES.PC1(key).buffer),
            C = CD.getUint32(0, false) >>> 4,
            D = CD.getUint32(3, false) & 0x0fffffff;
        for (let j = 1; j <= i; j++) {
            if (j === 1 || j === 2 || j === 9 || j === 16) {
                C = ((C << 1) & 0x0ffffffe) | ((C & 0x08000000) >>> 27);
                D = ((D << 1) & 0x0ffffffe) | ((D & 0x08000000) >>> 27);
            } else {
                C = ((C << 2) & 0x0ffffffc) | ((C & 0x0c000000) >>> 26);
                D = ((D << 2) & 0x0ffffffc) | ((D & 0x0c000000) >>> 26);
            }
        }

        CD.setUint32(0, (C << 4) >>> 0, false);
        CD.setUint32(3, (((C & 0x0f) << 28) | D) >>> 0, false);
        return TripleDES.PC2(new Uint8Array(CD.buffer));
    }

    static PC1(K) {
        return TripleDES.p(K, [57, 49, 41, 33, 25, 17,  9,
                                1, 58, 50, 42, 34, 26, 18,
                               10,  2, 59, 51, 43, 35, 27,
                               19, 11,  3, 60, 52, 44, 36,
                               63, 55, 47, 39, 31, 23, 15,
                                7, 62, 54, 46, 38, 30, 22,
                               14,  6, 61, 53, 45, 37, 29,
                               21, 13,  5, 28, 20, 12,  4]);
    }

    static PC2(K) {
        return TripleDES.p(K, [14, 17, 11, 24,  1,  5,
                                3, 28, 15,  6, 21, 10,
                               23, 19, 12,  4, 26,  8,
                               16,  7, 27, 20, 13,  2,
                               41, 52, 31, 37, 47, 55,
                               30, 40, 51, 45, 33, 48,
                               44, 49, 39, 56, 34, 53,
                               46, 42, 50, 36, 29, 32]);
    }
}

return TripleDES;
});

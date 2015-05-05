define(function () {
"use strict";

// rotating left shift
function rls (n, s) {
    return ((n << s) | (n >>> (32 - s))) >>> 0;
}

// implementation of the MD5 hash algorithm as specified in RFC 1321 section 3.
// no extra care or protection is given to guard against side-channel attacks, this function should only ever
// be used for cases where message is public anyway (e.g. public key fingerprints)
// this implementation passes all test cases in section A.5
// message should be an ArrayBuffer or ArrayBufferView
function md5(message) {
    var buffer, m;
    if (ArrayBuffer.isView(message)) {
        m = new Uint8Array(message.buffer, message.byteOffset, message.byteLength);
    } else {
        m = new Uint8Array(message);
    }

    // Step 1. Append Padding Bits
    // m will contain the padded message
    var s1length = m.length + 1;
    var mlength = m.length * 8;
    if (s1length % 64 > 56) {
        s1length += 56 + (64 - (s1length % 64));
    } else if (s1length % 64 < 56) {
        s1length += 56 - (s1length % 64);
    }
    s1length += 8;
    buffer = new ArrayBuffer(s1length);
    var temp = new Uint8Array(buffer);
    for (let i = 0; i < m.length; i++) {
        temp[i] = m[i];
    }
    temp[m.length] = 128; // 0b10000000
    m = temp;

    // Step 2. Append Length
    for (let i = 0; i < 8; i++) {
        if (mlength === 0) {
            break;
        }
        let lsb = mlength & 255;
        mlength >>>= 8;
        m[s1length - 8 + i] = lsb;
    }

    // Step 3. Initialize MD Buffer
    var A = 0x67452301,
        B = 0xefcdab89,
        C = 0x98badcfe,
        D = 0x10325476;

    // Step 4. Process Message in 16-Word Blocks
    var F = (X, Y, Z) => ((X & Y) | (~X & Z)) >>> 0,
        G = (X, Y, Z) => ((X & Z) | (Y & ~Z)) >>> 0,
        H = (X, Y, Z) => (X ^ Y ^ Z) >>> 0,
        I = (X, Y, Z) => (Y ^ (X | ~Z)) >>> 0;

    var T = [];
    for (let i = 1; i < 65; i++) {
        T[i] = (Math.floor(4294967296 * Math.abs(Math.sin(i))) & 0xffffffff) >>> 0;
    }

    var M = new DataView(m.buffer),
        N = M.byteLength / 4,
        X = [];

    var FF = (a, b, c, d, k, s, i) => b + rls(a + F(b, c, d) + X[k] + T[i], s),
        GG = (a, b, c, d, k, s, i) => b + rls(a + G(b, c, d) + X[k] + T[i], s),
        HH = (a, b, c, d, k, s, i) => b + rls(a + H(b, c, d) + X[k] + T[i], s),
        II = (a, b, c, d, k, s, i) => b + rls(a + I(b, c, d) + X[k] + T[i], s);

    for (let i = 0; i < N / 16; i++) {
        for (let j = 0; j < 16; j++) {
            // * 4 because DataViews expect a byte offset, while i * 16 + j is a word offset
            X[j] = M.getUint32((i * 16 + j) * 4, true);
        }

        let AA = A,
            BB = B,
            CC = C,
            DD = D;

        // Round 1.
        A = FF(A, B, C, D,  0,  7,  1);
        D = FF(D, A, B, C,  1, 12,  2);
        C = FF(C, D, A, B,  2, 17,  3);
        B = FF(B, C, D, A,  3, 22,  4);
        A = FF(A, B, C, D,  4,  7,  5);
        D = FF(D, A, B, C,  5, 12,  6);
        C = FF(C, D, A, B,  6, 17,  7);
        B = FF(B, C, D, A,  7, 22,  8);
        A = FF(A, B, C, D,  8,  7,  9);
        D = FF(D, A, B, C,  9, 12, 10);
        C = FF(C, D, A, B, 10, 17, 11);
        B = FF(B, C, D, A, 11, 22, 12);
        A = FF(A, B, C, D, 12,  7, 13);
        D = FF(D, A, B, C, 13, 12, 14);
        C = FF(C, D, A, B, 14, 17, 15);
        B = FF(B, C, D, A, 15, 22, 16);

        // Round 2.
        A = GG(A, B, C, D,  1,  5, 17);
        D = GG(D, A, B, C,  6,  9, 18);
        C = GG(C, D, A, B, 11, 14, 19);
        B = GG(B, C, D, A,  0, 20, 20);
        A = GG(A, B, C, D,  5,  5, 21);
        D = GG(D, A, B, C, 10,  9, 22);
        C = GG(C, D, A, B, 15, 14, 23);
        B = GG(B, C, D, A,  4, 20, 24);
        A = GG(A, B, C, D,  9,  5, 25);
        D = GG(D, A, B, C, 14,  9, 26);
        C = GG(C, D, A, B,  3, 14, 27);
        B = GG(B, C, D, A,  8, 20, 28);
        A = GG(A, B, C, D, 13,  5, 29);
        D = GG(D, A, B, C,  2,  9, 30);
        C = GG(C, D, A, B,  7, 14, 31);
        B = GG(B, C, D, A, 12, 20, 32);

        // Round 3.
        A = HH(A, B, C, D,  5,  4, 33);
        D = HH(D, A, B, C,  8, 11, 34);
        C = HH(C, D, A, B, 11, 16, 35);
        B = HH(B, C, D, A, 14, 23, 36);
        A = HH(A, B, C, D,  1,  4, 37);
        D = HH(D, A, B, C,  4, 11, 38);
        C = HH(C, D, A, B,  7, 16, 39);
        B = HH(B, C, D, A, 10, 23, 40);
        A = HH(A, B, C, D, 13,  4, 41);
        D = HH(D, A, B, C,  0, 11, 42);
        C = HH(C, D, A, B,  3, 16, 43);
        B = HH(B, C, D, A,  6, 23, 44);
        A = HH(A, B, C, D,  9,  4, 45);
        D = HH(D, A, B, C, 12, 11, 46);
        C = HH(C, D, A, B, 15, 16, 47);
        B = HH(B, C, D, A,  2, 23, 48);

        // Round 4.
        A = II(A, B, C, D,  0,  6, 49);
        D = II(D, A, B, C,  7, 10, 50);
        C = II(C, D, A, B, 14, 15, 51);
        B = II(B, C, D, A,  5, 21, 52);
        A = II(A, B, C, D, 12,  6, 53);
        D = II(D, A, B, C,  3, 10, 54);
        C = II(C, D, A, B, 10, 15, 55);
        B = II(B, C, D, A,  1, 21, 56);
        A = II(A, B, C, D,  8,  6, 57);
        D = II(D, A, B, C, 15, 10, 58);
        C = II(C, D, A, B,  6, 15, 59);
        B = II(B, C, D, A, 13, 21, 60);
        A = II(A, B, C, D,  4,  6, 61);
        D = II(D, A, B, C, 11, 10, 62);
        C = II(C, D, A, B,  2, 15, 63);
        B = II(B, C, D, A,  9, 21, 64);

        // Final step
        A = A + AA;
        B = B + BB;
        C = C + CC;
        D = D + DD;
    }

    // Step 5. Output
    var output = new ArrayBuffer(16),
        view = new DataView(output);
    view.setUint32(0, A, true);
    view.setUint32(4, B, true);
    view.setUint32(8, C, true);
    view.setUint32(12, D, true);

    return output;
}

return md5;
});

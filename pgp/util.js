define(function () {
"use strict";

function s2k(string, type, algo, salt, iterations) {
    // TODO: section 3.7.1
};
s2k.SIMPLE = 0;
s2k.SALTED = 1;
s2k.ITERATED_AND_SALTED = 3;

// returns a DataView of the data after parsing a new-style length at the given offset of the ArrayBuffer
// return format is an array [lengthBytes, DataView] so that overall it is lengthBytes + DataView.byteLength long
// the r parameter is for internal use only -- a value of "e" specifies that an error should be thrown upon
// encountering a partial length packet, a value of "s" specifies that the DataViews for each partial length should
// not be appended together into a new ArrayBuffer
function getData(data, offset, r) {
    var view = new DataView(data, offset),
        o1 = view.getUint8(0), o2;
    if (o1 < 192) {
        // one octet length
        return [1, new DataView(data, offset + 1, o1)];
    } else if (o1 < 224) {
        // two octet length
        o2 = view.getUint8(1);
        return [2, new DataView(data, offset + 2, ((o1 - 192) << 8) + o2 + 192)];
    } else if (o1 === 255) {
        // five octet length
        return [5, new DataView(data, offset + 5, view.getUint32(1, false))];
    } else {
        if (r === "e") {
            throw new Error("Unexpected data when parsing OpenPGP packet");
        }
        // partial length, accrue the entire stream into a new ArrayBuffer
        let partialLen = (1 << (o1 & 0x1f)) >>> 0,
            next = getData(data, offset + 1 + partialLen, "s");

        next[0] += 1;
        next.push(new DataView(data, offset + 1, partialLen));

        if (r !== "s") {
            let totalLen = 0;

            for (let i = 1; i < next.length; i++) {
                totalLen += next[i].byteLength;
            }

            let buf = new DataView(new ArrayBuffer(totalLen)),
                off = 0;

            for (let i = next.length - 1; i > 0; i--) {
                for (let j = 0; j < next[i].byteLength; j++) {
                    buf.setUint8(off, next[i].getUint8(j));
                    off++;
                }
            }

            return [next[0], buf];
        }
    }
}

return {
    s2k: s2k,
    getData: getData
};
});

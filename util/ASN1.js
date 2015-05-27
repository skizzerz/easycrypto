define(["./BinaryData", "./BigInt"], function (BinaryData, BigInt) {
"use strict";

// Utility class for working with ASN.1 schemas, including encoding/decoding into common formats:
// BER decoding and CER/DER encoding/decoding as specified in the 11/2008 revision of X.690.
// XER encoding/decoding as specified in the 11/2008 revision of X.693. This application supports decoding
//   BASIC-XER and encoding it using the Canonical XML Encoding rules. EXTENDED-XER is not supported.
class ASN1 {
    // constructs a new ASN.1 schema, which allows for encoding and decoding javascript objects into portable
    // representations as specified by the schema. At this time, the schema is not "proper" ASN.1 and instead simply
    // denotes how to transform our input into usable output. A proper ASN.1 parser may be forthcoming in the future.
    // schema may be left blank in order to do unstructured decoding (encoding is not permitted).
    constructor(schema) {
        
    }
    
    // data should be a BinaryData instance (BinaryData can be constructed from ArrayBuffer/ArrayBufferView and
    // hex/base64 strings)
    berDecode(binaryData) {
        var data = binaryData.buffer;
        
        var decoded = (function decodeItem(o, maxLength) {
            var item = {},
                needEOC = false,
                i = 1;
            
            // Step 1. parse identifier octects
            item.class = ["universal", "application", "context-specific", "private"][(data[o] & 0xc0) >> 6];
            item.primitive = (data[o] & 0x20) === 0;
            
            if (data[o] & 0x1f === 0x1f) {
                item.tag = BigInt.zero;
                
                if (data[o + 1] & 0x7f === 0) {
                    throw new Error("Invalid BER structure");
                }
                
                do {
                    item.tag = item.tag.shiftLeft(7).add(data[o + i] & 0x7f);
                } while (data[o + i++] & 0x80 !== 0);
            } else {
                item.tag = BigInt(data[o] & 0x1f);
            }
            
            // Step 2. parse length octets
            if (data[o + i] === 0x80) {
                // indefinite form
                if (item.primitive) {
                    throw new Error("Invalid BER structure");
                }
                
                needEOC = true;
                item.length = BigInt.zero;
                i++;
            } else if (data[o + i] & 0x80 === 0) {
                // short definite form
                item.length = BigInt(data[o + i] & 0x7f);
                i++;
            } else {
                // long definite form
                if (data[o + i] === 0xff) {
                    throw new Error("Invalid BER structure");
                }
                
                item.length = BigInt.zero;
                
                for (let j = 0; j < data[o + i] & 0x7f; j++) {
                    item.length = item.length.shiftLeft(8).add(data[o + i + j]);
                }
                
                i += data[o + i] & 0x7f;
            }
            
            if (maxLength !== undefined && item.length.gt(maxLength)) {
                throw new Error("Invalid BER structure");
            }
            
            // Step 3. parse contents octets
            // note: to do this for non-universal tags, we store off both the raw contents as well as attempt to
            // parse it as if it were a nested structure. If validation of the nested structure fails, we only return
            // the raw contents.
            
        })(0);
        
        // if we don't have a schema, return our generic form and cut out
        if (this.schema === undefined) {
            return decoded;
        }
        
        // TODO: convert generic form into structured form based on this.schema
        return decoded;
    }
}

return ASN1;
});

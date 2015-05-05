define(["./util", "./packet"], function (util, packet) {
"use strict";

// TODO: implementation of CAST5 encryption (listed as a SHOULD so could omit if necessary)

// implementation of OpenPGP as specified in RFC 4880, version 2.7
// this file is simply here to collect all other files into a single namespace
return {
    util: util,
    packet: packet
};
});

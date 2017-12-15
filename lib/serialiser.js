'use strict';

// vi: syntax=javascript ts=4

let InBuffer = require('./inbuffer'),
	internals = require('./internals');

class RNDC_Serialiser {

	constructor(key, algo) {

		key = new Buffer(key, 'base64');

		this.decode = (buf) => {
			let bs = new InBuffer(buf);
			let len = bs.nextInt();
			if (len != buf.length - 4) {
				throw new Error("RNDC buffer length mismatch");
			}

			let version = bs.nextInt();
			if (version !== 1) {
				throw new Error("Unknown RNDC protocol version");
			}

			let res = internals.table_fromwire(bs);
			let check = this.encode(res);
			if (Buffer.compare(buf, check) !== 0) {
				throw new Error("RNDC signature failure");
			}

			return res;
		}

		this.encode = (obj) => {
			delete obj._auth;
			let header = new Buffer(8);
			let databuf = internals.table_towire(obj, true);
			let sigbuf = internals.make_signature(algo, key, databuf);
			let length = header.length + sigbuf.length + databuf.length;
			let res = Buffer.concat([header, sigbuf, databuf], length);
			res.writeUInt32BE(length - 4, 0);		// length
			res.writeUInt32BE(0x01, 4);				// version
			return res;
		}
	}
}

module.exports = RNDC_Serialiser;

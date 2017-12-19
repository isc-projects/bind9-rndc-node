'use strict';

// vi: syntax=javascript ts=4

let crypto = require('crypto');

const MSGTYPE_STRING	 = 0x00;
const MSGTYPE_BINARYDATA = 0x01;
const MSGTYPE_TABLE		 = 0x02;
const MSGTYPE_LIST		 = 0x03;

const ISCCC_ALG_HMAC = {
	'md5':		157,
	'sha1':		161,
	'sha224':	162,
	'sha256':	163,
	'sha384':	164,
	'sha512':	165
};

//------

class RNDC_Internals {

	static binary_fromwire(bs) {
		return bs.nextString(bs.remaining());
	}

	static table_fromwire(bs) {
		let table = new Map(); // guarantees enumeration in insertion order
		while (!bs.empty()) {
			let key = this.key_fromwire(bs);
			let value = this.value_fromwire(bs);
			table[key] = value;
		}
		return table;
	}

	static list_fromwire() {
		let list = [];
		while (!bs.empty()) {
			list.push(this.value_fromwire(bs));
		}
		return list;
	}

	static key_fromwire(bs) {
		let len = bs.nextByte();
		return bs.nextString(len, 'ascii');
	}

	static value_fromwire(bs) {
		let type = bs.nextByte();
		let len = bs.nextInt();
		let buf = bs.slice(len);

		if (type === MSGTYPE_STRING || type == MSGTYPE_BINARYDATA) {
			return this.binary_fromwire(buf);
		} else if (type === MSGTYPE_TABLE) {
			return this.table_fromwire(buf);
		} else if (type === MSGTYPE_LIST) {
			return this.list_fromwire(buf);
		} else {
			throw new Error("Unknown RNDC message type: " + type);
		}
	}

	//------

	// <type> <length x 4> <data ...>
	static raw_towire(type, buffer) {
		let header = new Buffer(5 + buffer.length);
		header.writeUInt8(type, 0);
		header.writeUInt32BE(buffer.length, 1);
		buffer.copy(header, 5);
		return header;
	}

	static binary_towire(val) {
		let data = new Buffer(val, 'binary');
		return this.raw_towire(MSGTYPE_BINARYDATA, data);
	}

	static list_towire(val) {
		let bufs = val.map((v) => this.value_towire(v));
		let data = Buffer.concat(bufs);
		return this.raw_towire(MSGTYPE_LIST, data);
	}

	static table_towire(val, no_header) {
		let bufs = [];
		for (let key in val) {
			bufs.push(this.key_towire(key));
			bufs.push(this.value_towire(val[key]));
		}
		let data = Buffer.concat(bufs);

		if (no_header) {
			return data;
		} else {
			return this.raw_towire(MSGTYPE_TABLE, data);
		}
	}

	// <length x 1> <key data ...>
	static key_towire(key) {
		let length = Buffer.byteLength(key, 'ascii');
		let buf = new Buffer(length + 1);
		buf.writeUInt8(length, 0);
		buf.write(key, 1, length, 'ascii');
		return buf;
	}

	static value_towire(val) {
		if (Array.isArray(val)) {
			return this.list_towire(val);
		} else if (typeof val === 'object') {
			return this.table_towire(val);
		} else {
			return this.binary_towire(val.toString());
		}
	}

	//------

	static make_signature(algo, key, buf) {
		let hmac = crypto.createHmac(algo, key).update(buf);
		let type = 'h' + algo.substring(0, 3).toLowerCase();	// hmd5 or hsha
		let sig = hmac.digest('base64');
		if (type === 'hmd5') {	// no padding on hmd5
			sig = sig.replace(/=*$/, '');
		} else {
			let buf = new Buffer(89);
			buf.fill(0);
			buf[0] = ISCCC_ALG_HMAC[algo] || 0;
			buf.write(sig, 1);
			sig = buf.toString('binary');
		}
		let table = { _auth: { [type]: sig } };
		return this.table_towire(table, true);
	}
}

//------

module.exports = RNDC_Internals;

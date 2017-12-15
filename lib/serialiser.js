'use strict';

// vi: syntax=javascript ts=4

let crypto = require('crypto'),
	InBuffer = require('./inbuffer');

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

function binary_fromwire(bs) {
	return bs.nextString(bs.remaining());
}

function table_fromwire(bs) {
	let table = new Map(); // guarantees enumeration in insertion order
	while (!bs.empty()) {
		let key = key_fromwire(bs);
		let value = value_fromwire(bs);
		table[key] = value;
	}
	return table;
}

function list_fromwire() {
	let list = [];
	while (!bs.empty()) {
		list.push(value_fromwire(bs));
	}
	return list;
}

function key_fromwire(bs) {
	let len = bs.nextByte();
	return bs.nextString(len, 'ascii');
}

function value_fromwire(bs) {
	let type = bs.nextByte();
	let len = bs.nextInt();
	let buf = bs.slice(len);

	if (type === MSGTYPE_STRING || type == MSGTYPE_BINARYDATA) {
		return binary_fromwire(buf);
	} else if (type === MSGTYPE_TABLE) {
		return table_fromwire(buf);
	} else if (type === MSGTYPE_LIST) {
		return list_fromwire(buf);
	} else {
		throw new Error("Unknown RNDC message type: " + type);
	}
}

//------

function raw_towire(type, buffer) {
	let header = new Buffer(5 + buffer.length);
	header.writeUInt8(type, 0);
	header.writeUInt32BE(buffer.length, 1);
	buffer.copy(header, 5);
	return header;
}

function binary_towire(val) {
	let data = new Buffer(val, 'binary');
	return raw_towire(MSGTYPE_BINARYDATA, data);
}

function list_towire(val) {
	let bufs = val.map((v) => value_towire(v));
	let data = Buffer.concat(bufs);
	return raw_towire(MSGTYPE_LIST, data);
}

function table_towire(val, no_header) {
	let bufs = [];
	for (let key in val) {
		bufs.push(key_towire(key));
		bufs.push(value_towire(val[key]));
	}
	let data = Buffer.concat(bufs);

	if (no_header) {
		return data;
	} else {
		return raw_towire(MSGTYPE_TABLE, data);
	}
}

function key_towire(key) {
	let length = Buffer.byteLength(key, 'ascii');
	let buf = new Buffer(length + 1);
	buf.writeUInt8(length, 0);
	buf.write(key, 1, length, 'ascii');
	return buf;
}

function value_towire(val) {
	if (Array.isArray(val)) {
		return list_towire(val);
	} else if (typeof val === 'object') {
		return table_towire(val);
	} else {
		return binary_towire(val.toString());
	}
}

//------

function make_signature(algo, key, buf) {
	let hmac = crypto.createHmac(algo, key).update(buf);
	let type = 'h' + algo.substring(0, 3).toLowerCase();
	let sig = hmac.digest('base64');
	if (type === 'hmd5') {
		sig = sig.replace(/=*$/, '');
	} else {
		let buf = new Buffer(89);
		buf.fill(0);
		buf[0] = ISCCC_ALG_HMAC[algo] || 0;
		buf.write(sig, 1);
		sig = buf.toString('binary');
	}
	let table = { _auth: { [type]: sig } };
	return table_towire(table, true);
}

//------

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

			let res = table_fromwire(bs);
			let check = this.encode(res);
			if (Buffer.compare(buf, check) !== 0) {
				throw new Error("RNDC signature failure");
			}

			return res;
		}

		this.encode = (obj) => {
			delete obj._auth;
			let header = new Buffer(8);
			let databuf = table_towire(obj, true);
			let sigbuf = make_signature(algo, key, databuf);
			let length = header.length + sigbuf.length + databuf.length;
			let res = Buffer.concat([header, sigbuf, databuf], length);
			res.writeUInt32BE(length - 4, 0);		// length
			res.writeUInt32BE(0x01, 4);				// version
			return res;
		}
	}
}

module.exports = RNDC_Serialiser;

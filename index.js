'use strict';

// vi: syntax=javascript ts=4

let crypto = require('crypto'),
	net = require('net'),
	EventEmitter = require('events');

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

// limited functionality wrapper for a buffer that remembers
// the current read position within the buffer

class InBuffer {
	constructor(buffer) {
		this.buffer = buffer;
		this.offset = 0;
	}

	nextByte() {
		let res = this.buffer.readUInt8(this.offset);
		this.offset += 1;
		return res;
	}

	nextInt() {
		let res = this.buffer.readUInt32BE(this.offset);
		this.offset += 4;
		return res;
	}

	nextString(n, encoding) {
		encoding = encoding || 'binary';
		let res = this.buffer.slice(this.offset, this.offset + n).toString(encoding);
		this.offset += n;
		return res;
	}

	slice(n) {
		let res = this.buffer.slice(this.offset, this.offset + n);
		this.offset += n;
		return new InBuffer(res);
	}

	remaining() {
		return Math.max(this.buffer.length - this.offset, 0);
	}

	empty() {
		return this.remaining() <= 0;
	}
}

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

class Session extends EventEmitter {

	constructor(host, port, key, algo) {
		super();

		key = new Buffer(key, 'base64');
		let serial = Math.floor(Math.pow(2, 32) * Math.random());
		let buffer = new Buffer([]);
		let nonce;

		let decode = (buf) => {
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
			let check = encode(res);
			if (Buffer.compare(buf, check) !== 0) {
				throw new Error("RNDC signature failure");
			}

			return res;
		}

		let encode = (obj) => {
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

		let send = (obj) => {
			const now = Math.floor(Date.now() / 1000);
			let ctrl = obj._ctrl = obj._ctrl || new Map();
			ctrl._ser = ++serial;
			ctrl._tim = now;
			ctrl._exp = now + 60;
			socket.write(encode(obj));
		}

		let handle_packet = (packet) => {
			let resp = decode(packet);
			if (nonce === undefined) {
				if (resp && resp._ctrl && resp._ctrl._nonce) {
					nonce = resp._ctrl._nonce;
					this.emit('ready');
				} else {
					this.emit(new Error('RNDC nonce not received'));
				}
			} else {
				this.emit('data', resp._data);
			}
		}

		let socket = net.connect(port, host, () => {
			send({_data: {type: 'null'}}); // send null command to receive nonce
		});

		socket.setTimeout(30000);

		socket.on('data', (data) => {
			buffer = Buffer.concat([buffer, data]);
			if (buffer.length >= 4) {
				let len = buffer.readUInt32BE(0);
				if (buffer.length >= 4 + len) {
					let packet = buffer.slice(0, 4 + len);
					handle_packet(packet);
					buffer = buffer.slice(4 + len);
				}
			}
		});

		socket.on('timeout', () => {
			console.log('error: socket timeout');
			this.emit('timeout');
		});

		socket.on('error', (e) => {
			this.emit('error', e);
		});

		socket.on('end', () => {
			if (nonce === undefined) {
				this.emit('error', new Error('RNDC handshake incomplete'));
			}
			if (buffer.length > 0) {
				console.log('warning: unread data left over');
			}
			this.emit('end');
		});

		this.send = (cmd) => {
			send({_ctrl: {_nonce: nonce}, _data: {type: cmd}});
		};

		this.end = () => {
			socket.end();
		};
	}
}

function connect(host, port, key, algo) {
	return new Session(host, port, key, algo);
}

module.exports = { connect };

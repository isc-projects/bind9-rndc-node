'use strict';

// vi: syntax=javascript ts=4

let crypto = require('crypto'),
	net = require('net'),
	EventEmitter = require('events'),
	RNDC_Serialiser = require('./serialiser');

class RNDC_Protocol extends EventEmitter {

	constructor(host, port, key, algo) {
		super();

		let serialiser = new RNDC_Serialiser(key, algo);

		let serial = Math.floor(Math.pow(2, 32) * Math.random());
		let nonce;
		let buffer = new Buffer([]);

		let send = (obj) => {
			const now = Math.floor(Date.now() / 1000);
			let ctrl = obj._ctrl = obj._ctrl || new Map();
			ctrl._ser = ++serial;
			ctrl._tim = now;
			ctrl._exp = now + 60;
			socket.write(serialiser.encode(obj));
		}

		let handle_packet = (packet) => {
			let resp = serialiser.decode(packet);
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
		}

		this.end = () => {
			socket.end();
		}
	}
}

module.exports = RNDC_Protocol;

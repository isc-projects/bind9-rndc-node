'use strict';

// vi: syntax=javascript ts=4

let crypto = require('crypto'),
	net = require('net'),
	EventEmitter = require('events'),
	RNDC_Serialiser = require('./serialiser');

/**
 * Class encapsulating a connection to a BIND9 server's rndc port
 * @extends EventEmitter
 */
class RNDC_Protocol extends EventEmitter {

	/**
	 * Constructs an RNDC_Protocol object that makes a connection to the
	 * specified host and port and initiates the rndc protocol using the given
	 * key and algorithm.
	 * @param {string} host - the BIND9 server hostname
	 * @param {number} port - the BIND9 server's rndc port
	 * @param {string} key - the rndc shared key, in base64 format
	 * @param {string} algo - the rndc shared algorithm (e.g. "sha256")
	 */
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
			let old_nonce = nonce;

			let resp = serialiser.decode(packet);
			if (resp && resp._ctrl && resp._ctrl._nonce) {
				nonce = resp._ctrl._nonce;
			}

			if (old_nonce === undefined) {
				if (nonce) {
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

		/**
		 * sends the specified command to the BIND9 server.
		 * @param {string} cmd - the command
		 */
		this.send = (cmd) => {
			send({_ctrl: {_nonce: nonce}, _data: {type: cmd}});
		}

		/**
		 * terminates the rndc connection.
		 */
		this.end = () => {
			socket.end();
		}
	}
}

module.exports = RNDC_Protocol;

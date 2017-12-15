'use strict';

// vi: syntax=javascript ts=4

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

module.exports = InBuffer;

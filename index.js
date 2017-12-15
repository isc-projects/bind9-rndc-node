'use strict';

// vi: syntax=javascript ts=4

const RNDC_Protocol = require('./lib/protocol');

function connect(host, port, key, algo) {
	return new RNDC_Protocol(host, port, key, algo);
}

module.exports = { connect };

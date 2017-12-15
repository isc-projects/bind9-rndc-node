// vi: syntax=javascript ts=4

const assert = require('assert');

const internals = require('../lib/internals');

describe('RNDC_Internals', () => {

	describe('.raw_towire', () => {

		it('should correctly encode an empty buffer', () => {
			assert.deepEqual(internals.raw_towire(2, Buffer.from("")),
							 Buffer.from([2, 0, 0, 0, 0]));
		});

		it('should correctly encode a string buffer', () => {
			assert.deepEqual(internals.raw_towire(1, Buffer.from("abc")),
							 Buffer.from([1, 0, 0, 0, 3, 97, 98, 99]));
		});

	});

	describe('.binary_towire', () => {

		it('should correctly encode an empty string', () => {
			assert.deepEqual(internals.binary_towire(''),
							 Buffer.from([1, 0, 0, 0, 0]));
		});

		it('should correctly encode a string', () => {
			assert.deepEqual(internals.binary_towire("abc"),
							 Buffer.from([1, 0, 0, 0, 3, 97, 98, 99]));
		});

	});

	describe('.list_towire', () => {

		it('should correctly encode an empty list', () => {
			assert.deepEqual(internals.list_towire([]),
							 Buffer.from([3, 0, 0, 0, 0]));
		});

		it('should correctly encode a list of strings', () => {
			assert.deepEqual(internals.list_towire(["abc", "ABC"]),
							 Buffer.from([
								3, 0, 0, 0, 16,
								1, 0, 0, 0,  3, 97, 98, 99,
								1, 0, 0, 0,  3, 65, 66, 67,
							]));
		});

	});

	describe('.table_towire', () => {

		it('should correctly encode an empty table', () => {
			assert.deepEqual(internals.table_towire({}),
							 Buffer.from([2, 0, 0, 0, 0]));
		});

		it('should correctly encode a table of strings', () => {
			assert.deepEqual(internals.table_towire({ K1: "abc", K2: "ABC"}),
							 Buffer.from([
								2, 0, 0, 0, 22,
								2, 75, 49,
								1, 0, 0, 0,  3, 97, 98, 99,
								2, 75, 50,
								1, 0, 0, 0,  3, 65, 66, 67,
							]));
		});

	});

});

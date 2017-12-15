// vi: syntax=javascript ts=4

const assert = require('assert');

const InBuffer = require('../lib/inbuffer');

describe('InBuffer', () => {

	let testbuf = new InBuffer(Buffer.from([1, 2, 3, 4, 5, 65, 66, 67]));

	describe('#remaining', () => {
		it('should return 8 bytes remaining when first initialised', () => {
			assert.equal(testbuf.remaining(), 8);
		});

		it('should not be empty when first initialised', () => {
			assert.equal(testbuf.empty(), false);
		});
	});

	describe('#nextByte', () => {
		it('should return 1 when reading the first byte', () => {
			assert.equal(testbuf.nextByte(), 1);
		});

		it('should leave 7 bytes remaining', () => {
			assert.equal(testbuf.remaining(), 7);
		});
	});

	describe('#nextInt', () => {
		it('should return 0x02030405 when reading the first int', () => {
			assert.equal(testbuf.nextInt(), 0x02030405);
		});

		it('should leave 3 bytes remaining', () => {
			assert.equal(testbuf.remaining(), 3);
		});
	});


	describe('#nextString', () => {
		it('should return "ABC" when reading the next 3 char string', () => {
			assert.equal(testbuf.nextString(3), "ABC"); 
		});

		it('should leave no bytes remaining', () => {
			assert.equal(testbuf.remaining(), 0);
		});

		it('should now be empty', () => {
			assert.equal(testbuf.empty(), true);
		});
	});

	describe('#nextByte', () => {
		it('should throw a RangeError exception when reading an empty buffer', () => {
			assert.throws(() => {
				testbuf.nextByte();
			},
			RangeError);
		});
	});
});

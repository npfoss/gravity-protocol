// for eslint
/* globals describe it */

const assert = require('assert');
const GravityProtocol = require('..');

const gp = new GravityProtocol();

describe('Array', () => {
  describe('#indexOf()', () => {
    it('should return -1 when the value is not present', () => {
      assert.equal([1, 2, 3].indexOf(4), -1);
    });
  });
});

describe('crypto', () => {
  describe('symmetric enc/dec', () => {
    it('should decrypt to the input', () => {
      const key = Uint8Array.from([174, 105, 87, 232, 248, 157, 181, 119, 252, 184, 170, 120, 177, 112, 31, 137, 251, 222, 213, 199, 216, 167, 148, 100, 18, 32, 215, 222, 13, 149, 46, 80]);
      // more stuff
    });
  });
});


gp.stop().then(() => {});
// PROBLEM: doesn't actually stop everything (IPFS still printing stuff)

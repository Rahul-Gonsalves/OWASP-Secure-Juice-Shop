// Runnable self-check: node test.js  (no framework)
const assert = require('assert');
const { hashPassword, verifyPassword, validateCredentials, escapeHtml } = require('./auth');

// validation
assert.deepStrictEqual(validateCredentials('', ''), ['Email and password are required.']);
assert.deepStrictEqual(validateCredentials('noat', 'longenough'), ['Email must contain "@".']);
assert.deepStrictEqual(validateCredentials('a@b.c', 'short'), ['Password must be at least 8 characters.']);
assert.deepStrictEqual(validateCredentials('a@b.c', 'longenough'), []);

// password hashing round-trip
const h = hashPassword('correct horse');
assert.ok(verifyPassword('correct horse', h), 'right password should verify');
assert.ok(!verifyPassword('wrong', h), 'wrong password should fail');
assert.notStrictEqual(hashPassword('x'), hashPassword('x'), 'salt makes hashes differ');

// XSS escaping
assert.strictEqual(escapeHtml('<script>alert(1)</script>'),
  '&lt;script&gt;alert(1)&lt;/script&gt;');

console.log('All checks passed.');

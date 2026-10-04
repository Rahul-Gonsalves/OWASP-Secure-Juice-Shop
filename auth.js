// Pure, testable security helpers. No dependencies — uses Node built-ins only.
const crypto = require('crypto');

// Password hashing with scrypt (a memory-hard KDF, same job as bcrypt, zero deps).
// Format stored: "<saltHex>:<hashHex>".
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return salt.toString('hex') + ':' + hash.toString('hex');
}

function verifyPassword(password, stored) {
  const [saltHex, hashHex] = String(stored).split(':');
  if (!saltHex || !hashHex) return false;
  const hash = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), 64);
  // timingSafeEqual needs equal-length buffers; scrypt output is fixed 64 bytes.
  return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

// Server-side validation — never trust the client-side checks.
function validateCredentials(email, password) {
  const errors = [];
  if (!email || !password) errors.push('Email and password are required.');
  if (email && !String(email).includes('@')) errors.push('Email must contain "@".');
  if (password && String(password).length < 8) errors.push('Password must be at least 8 characters.');
  return errors;
}

// Output encoding — the XSS defense. Any user value shown back goes through this.
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

module.exports = { hashPassword, verifyPassword, validateCredentials, escapeHtml };

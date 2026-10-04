// Zero-dependency login server. Run: node server.js  →  http://localhost:3000
const http = require('http');
const fs = require('fs');
const path = require('path');
const { hashPassword, verifyPassword, validateCredentials, escapeHtml } = require('./auth');

// In-memory "database". Lookup is a JS .find() — no SQL string is ever built,
// so SQL injection is structurally impossible. Against a real DB you'd use a
// parameterized/prepared statement, e.g.:
//   db.prepare('SELECT * FROM users WHERE email = ?').get(email)   // safe
//   db.query("SELECT * FROM users WHERE email = '" + email + "'")  // VULNERABLE
const users = [
  { email: 'admin@juice.test', passwordHash: hashPassword('admin12345') },
];

const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');

function send(res, code, type, body) {
  res.writeHead(code, { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff' });
  res.end(body);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/') return send(res, 200, 'text/html', html);

  if (req.method === 'POST' && req.url === '/login') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e4) req.destroy(); });
    req.on('end', () => {
      let email = '', password = '';
      try { ({ email = '', password = '' } = JSON.parse(body || '{}')); } catch { /* ignore */ }

      // 1) Server-side validation (defense in depth — client checks can be bypassed).
      const errors = validateCredentials(email, password);
      if (errors.length) return send(res, 400, 'application/json',
        JSON.stringify({ ok: false, message: errors.join(' ') }));

      // 2) Safe lookup + constant-time password verify.
      const user = users.find(u => u.email === email);
      const ok = user && verifyPassword(password, user.passwordHash);

      // escapeHtml on the reflected email neutralizes XSS even if a client ever
      // rendered this message as HTML.
      return send(res, ok ? 200 : 401, 'application/json', JSON.stringify({
        ok: !!ok,
        message: ok ? 'Login successful.' : `Invalid credentials for ${escapeHtml(email)}.`,
      }));
    });
    return;
  }

  send(res, 404, 'text/plain', 'Not found');
});

if (require.main === module) {
  server.listen(3000, () => console.log('Running at http://localhost:3000'));
}
module.exports = server;

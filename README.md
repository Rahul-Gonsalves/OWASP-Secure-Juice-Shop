# Juice Shop Login Form (CSCE477 HW2-B)

A minimal login page that mimics OWASP Juice Shop's login, built to demonstrate
basic web-security defenses: client-side **and** server-side validation,
password hashing, parameterized-style lookups (no SQL string building), and
output encoding against XSS.

**Zero dependencies** — it uses only Node.js built-in modules, so there is no
`npm install` step that can fail.

## What it does

- Email + password login form (`public/index.html`)
- **Client-side validation** (JavaScript): blocks empty submits, requires the
  email to contain `@`, and requires the password to be at least 8 characters
- **Server-side validation** (`server.js` + `auth.js`): the server re-checks the
  same rules, because client-side checks can be bypassed
- **Password hashing** with `crypto.scrypt` (a memory-hard KDF, same role as
  bcrypt) with a random per-password salt and constant-time comparison
- **XSS defense**: any reflected user input is HTML-escaped on the server and
  rendered with `textContent` (never `innerHTML`) on the client
- **SQLi defense**: user lookup is an in-memory `.find()` — no SQL string is
  ever concatenated. `server.js` documents the parameterized-query equivalent
  for a real database.

## How to run

Requires Node.js (v18+).

```bash
node server.js
# open http://localhost:3000
```

Test login: `admin@juice.test` / `admin12345`

## Run the tests

```bash
node test.js
```

## Project structure

| File | Purpose |
|------|---------|
| `public/index.html` | The form + client-side validation |
| `server.js` | HTTP server, routing, server-side validation |
| `auth.js` | Pure helpers: hashing, validation, HTML escaping |
| `test.js` | Assertions for the helpers |

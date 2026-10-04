# CSCE477 HW2-B — Submission

GitHub repo: **<PASTE YOUR PUBLIC REPO URL HERE>**

---

## Part 1 — Secure Feature Design (Juice Shop)

I exploited three vulnerabilities in OWASP Juice Shop.
**(1) SQL Injection login bypass:** entering `' OR 1=1--` as the email with any
password logs me in as the first user (admin). *Fix:* parameterized/prepared
statements (`WHERE email = ?`) and an ORM, so input is never parsed as SQL.
**(2) DOM XSS in search:** the payload `<iframe src="javascript:alert('xss')">`
in the search bar executes script. *Fix:* contextual output encoding, framework
auto-escaping, DOM sanitization, and a Content-Security-Policy. **(3) Broken
access control / mass assignment:** POSTing to `/api/Users` with `"role":"admin"`
creates an admin account. *Fix:* server-side authorization and a field allowlist
so client-supplied roles are ignored. Passwords should be salted and hashed with
bcrypt/scrypt, e.g. `bcrypt.hash(password, 12)`.

---

## Part 2 — Implementation Write-up

I built a zero-dependency Node.js login form that mirrors Juice Shop's login.
The front end (`index.html`) does **client-side validation** — it blocks empty
submissions and checks the email contains `@` and the password is ≥ 8 characters
— then POSTs JSON to the server. The server (`server.js` + `auth.js`) performs
**server-side validation** of the same rules, because client checks can be
bypassed. Security measures baked in: passwords stored with salted `scrypt`
hashing and constant-time comparison; user lookup via in-memory `.find()` (no SQL
string building, with the parameterized-query equivalent documented); and all
reflected input HTML-escaped server-side and rendered with `textContent` to stop
XSS. `node test.js` verifies the logic.

---

## Part 3 — Exploiting My Own Form

I attempted SQL Injection, XSS, and client-validation bypass against my form.
**SQLi:** submitting `admin@juice.test' OR '1'='1` had no effect — the lookup is
a JS `.find()`, so the string is treated as a literal email and never matches;
no SQL is parsed. **XSS:** submitting `<script>alert(1)</script>@x.com` did
**not** execute. The server returned the value HTML-escaped
(`&lt;script&gt;...`) and the client renders it with `textContent`, so it shows
as plain text. **Bypass:** I skipped the browser entirely with `curl` and sent an
empty email/password — the client-side check never ran, but the server still
rejected it ("Email and password are required."), proving defense in depth.
The attacks failed, which is the intended result. *If I had rendered replies with
`innerHTML`, the XSS would fire;* the fix is the output encoding + `textContent`
already in place.

---

### Screenshots to capture (replace these notes with images)

- **Part 1:** one screenshot per Juice Shop exploit (SQLi login success as admin,
  the XSS `alert` popup, the admin account created via the API).
- **Part 3:** the form in the browser; the SQLi attempt rejected; the
  `<script>` payload shown as text (not an alert); the `curl` empty-field attempt
  returning the server rejection.

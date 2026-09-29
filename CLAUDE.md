# Project Ludlow: standing instructions

Project Ludlow lets workers form a union with zero-knowledge authorization cards, then run it democratically and verifiably. Read `README.md` first, `docs/PROTOCOL.md` for the cryptography, and `docs/spec/BUILD_PROMPT.md` and `docs/spec/BUILD_PROMPT_V2.md` for the original specifications (the V2 document doubles as the roadmap).

## Non-negotiable rules (these override convenience; if a task seems to need breaking one, stop and ask)

### Privacy and data
1. **No plaintext personal data is persisted by the campaign system.** Names, emails, phones, employer and union names, and card contents exist on the server only as ciphertext. The one exception is the Confirmation Transmission endpoint, which receives the signer's details, sends the email and discards them (only `confirmation_sent_at` and the provider's message id are stored).
2. **Never log request bodies, query strings, headers, tokens or IP addresses.** `server/log.js` has an allowlist (method, route *pattern*, status, duration). Do not add fields to it.
3. **Secrets in URLs go in the fragment (`#...`), never the path or query.** All tokens and keys are generated in the browser; the server stores only hashes (SHA-256 of 32 random bytes). Never hash low-entropy personal data as a "privacy" measure.
4. **Never collect** dates of birth, SSNs, employee ids, paystub data or government ids.
5. Rate limiting is in-memory, keyed by `SHA-256(ip + daily salt)`. Nothing about IPs is persisted.
6. **Workspace personal data is encrypted at rest** (envelope encryption, `server/kms.js`). **Grievances, private records and reports are end-to-end**: the server must never hold a key that opens them.
7. **Ballots are unlinkable.** `ws_ballots` and `ws_vote_receipts` have no member reference and no timestamp. Do not add either. Do not log anything with an identity next to a ballot request.
8. Representation is never gated by dues or membership (grievances, the procedure, contract and rights pages are open to every unit employee).

9a. **The release number is enforced by the server.** `export-bundle` is the only route that may return card ciphertext, and it must check `release_min` first. Never add another route that returns ciphertext, and never let one trustee lower the number alone.
9b. **Cards are sealed 'solo' to the founder only while the committee is incomplete.** Never accept a solo card once every trustee has joined, and never let anyone but trustee 1 reshare.

### Cryptography
9. Only `libsodium-wrappers-sumo` and `shamir-secret-sharing`, all in `shared/crypto.js`. Never write primitives. Never use `Math.random()` for anything security related.
10. Every crypto function has tests, including negative ones (wrong key, k-1 shares, tampering).

### Frontend
11. **No third-party scripts, analytics, CDNs, external fonts or images.** Strict CSP (`script-src 'self' 'wasm-unsafe-eval'`; the WASM flag only lets libsodium compile, it does not allow JS eval). **No `innerHTML`, `eval` or inline scripts/styles anywhere** (a test greps for it). Build DOM with `web/src/ui.js`.
12. No cookies. Credentials live in the browser (key files, member secret) or in memory.

### Legal content
13. Every legal text lives in `content/legal/` with the header `DRAFT — REQUIRES REVIEW BY A LICENSED LABOR ATTORNEY BEFORE REAL-WORLD USE`. Mark uncertainty with `TODO(lawyer):` / `TODO(accountant):`. Never invent legal requirements.
14. The platform never files anything, contacts an employer or sends anything to an agency. It prepares drafts for humans. Never let generated documents claim a majority the numbers do not show.
15. The UI must never say a card will be used "only" for an election.
16. Online officer elections stay behind `ONLINE_OFFICER_ELECTIONS` (off by default).

### Engineering
17. Every permission is data in `shared/permissions.js` and every workspace route is registered through `W()`. The matrix test walks the route table; keep it passing.
18. Keep dependencies minimal (runtime: libsodium, shamir, better-sqlite3, pdf-lib). Justify any new one.
19. Every feature ships with tests. The plaintext-leak tests must pass on every change.

## Architecture in one screen
- `shared/` runs in browser and Node: `crypto.js`, `permissions.js`, `deadlines.js`, `constants.js`, `verify.js`.
- `server/`: plain Node `http`, tiny router (`http.js`), SQLite (`db.js`), `campaign.js` (zero-knowledge cards), `workspace.js` (running the union), `mail.js`, `kms.js`.
- `web/`: vanilla JS single-page app bundled by esbuild (`scripts/build.js`). Legal rules per country are data in `web/src/packs.js` + `content/legal/<pack>/`.
- `test/`: `unit`, `campaign`, `workspace` (API, in-process) and `e2e` (real Chromium, real CSP).

## Commands
`npm start` (build + run), `npm test` (everything), `node --test test/unit.test.js` (fast).

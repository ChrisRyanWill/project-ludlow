# Build Prompt: Encrypted Union Authorization Card Platform (MVP)

You are the lead engineer building the MVP of a web platform that lets workers collect **legally valid electronic union authorization cards** for their workplace, keep every signer's identity encrypted so that **the server cannot read it**, and — when the organizing committee decides to go public — produce a complete, correctly formatted package for demanding recognition or filing an NLRB election petition.

Read this entire document before writing any code. It is the source of truth.

---

## 0. First actions (do these before anything else)

1. Create `CLAUDE.md` in the repo root containing **Section 2 (Non-negotiable rules)** and **Section 3 (Architecture summary)** verbatim. This is your standing instruction file for every future session.
2. Create `docs/SPEC.md` containing this entire document verbatim.
3. Create `docs/THREAT_MODEL.md` from Section 4.
4. Then begin **Phase 0** (Section 12). Work one phase at a time. At the end of each phase: run all tests, commit with a clear message, and **stop and summarize** what was built, what was tested, and any decisions or open questions for me. Do not start the next phase until I say so.

If anything in this spec is ambiguous or seems wrong, stop and ask rather than guessing. If you believe a requirement is technically unsound, say so and propose an alternative.

---

## 1. Product summary

**What it is:** A tool, not a union and not a law firm. Workers use it to form their *own* independent union (or support any union they choose) at their workplace.

**Core flow:**
1. A small committee of trusted coworkers (the **trustees**, 3–5 people) creates a campaign.
2. They invite coworkers with private links shared through their own phones (Signal, iMessage, WhatsApp, etc.).
3. Coworkers sign an electronic authorization card. The card is **encrypted in their browser** before it is sent. Nobody — not the server, not any single trustee — can read it.
4. Coworkers who arrived via a shared group link must be **vouched** in person by the person who invited them before their card counts.
5. The dashboard shows progress toward 30% (enough to petition for an election), 50%+1 (majority), and a recommended 65–70% supermajority.
6. When the committee decides to go public, **k of n trustees** meet (ideally in person), combine their keys **in the browser**, decrypt the cards **locally**, and download a package: roster, per-signer card PDFs, a draft declaration, a draft recognition demand letter, a pre-filled NLRB Form 502, and a filing checklist.
7. Humans review and file. The platform never files anything or contacts the employer automatically.

**Legal basis for the card data (NLRB GC Memo 15-08, Revised Oct. 26, 2015).** Every electronic card must contain:
- (a) signer's name
- (b) signer's email address or other known contact info
- (c) signer's telephone number
- (d) the exact language the signer agreed to
- (e) the date the signature was submitted
- (f) the name of the employer

The submitting party must also file a **declaration** identifying the signature technology and explaining how its controls ensure the signature is the employee's own and that what was submitted matches what they saw and signed. For simple (non-PKI) electronic signatures, the submitter must promptly send a **Confirmation Transmission** to an account the signer provided, restating all of (a)–(f), and must provide any responses received to the NLRB. Cards must **not** contain dates of birth, Social Security numbers, or other sensitive personal identifiers.

The design below exists to meet those requirements while exposing as little as possible.

---

## 2. Non-negotiable rules (copy into CLAUDE.md)

These rules override convenience. If a task seems to require breaking one, stop and ask.

### Privacy and data handling
1. **No plaintext personal data is ever persisted on the server.** Names, emails, phone numbers, employer names, union names, job titles, and card contents exist on the server only as ciphertext. The single exception is the Confirmation Transmission endpoint (rule 2).
2. The confirmation endpoint receives the signer's email and card fields in the request body, sends the email, and **discards them**. It must not write them to the database, logs, error trackers, queues, or temp files. It stores only `confirmation_sent_at` and the provider's message ID.
3. **Never log request bodies, query strings, headers containing tokens, or IP addresses.** Use a structured logger with an explicit allowlist of fields (method, route pattern, status code, duration). Log route *patterns* (`/api/cards/:id`), never raw paths.
4. **All secret tokens and keys in URLs go in the fragment (`#...`), never the path or query string**, so they never reach the server or its logs. The client reads the fragment and sends what's needed in a POST body.
5. Store only **hashes** of bearer tokens (SHA-256 of 32 random bytes is fine because tokens are high-entropy). Never hash low-entropy personal data (phone numbers, emails, employee IDs) as a privacy measure — it is trivially reversible. Just don't store it.
6. Never collect dates of birth, SSNs, employee ID numbers, paystub data, or government IDs.
7. Rate limiting uses **in-memory** counters keyed by `SHA-256(ip + in-memory salt that rotates daily)`. Nothing about IPs is persisted.

### Cryptography
8. Use only **`libsodium-wrappers-sumo`** and **`shamir-secret-sharing`** for cryptography. Never implement cryptographic primitives yourself. Never use `Math.random()` for anything security-related.
9. All encryption and decryption of card contents happens **in the browser**. The server never receives a key capable of decrypting cards or campaign metadata.
10. Every crypto function lives in `packages/crypto` with unit tests, including negative tests (wrong key fails, k−1 shares fail, tampered ciphertext fails).

### Frontend security
11. **No third-party scripts, analytics, trackers, CDNs, externally hosted fonts, or external images.** Self-host everything. Every third-party request leaks a worker's IP address.
12. Strict Content-Security-Policy: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. No inline scripts. No `eval`.
13. Headers on every response: `Referrer-Policy: no-referrer`, `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, `X-Content-Type-Options: nosniff`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `Cross-Origin-Opener-Policy: same-origin`.
14. No cookies for tracking. Member and trustee credentials live in the browser (localStorage / IndexedDB) and are sent as bearer tokens or signed challenges.
15. Email provider **open tracking and click tracking must be disabled** (click tracking rewrites links through the provider's domain).

### Legal content
16. Every piece of legal text (card language, declaration, demand letter, checklists, rights info) lives as a Markdown file in `/content/legal/` with a header line `DRAFT — REQUIRES REVIEW BY A LICENSED LABOR ATTORNEY BEFORE REAL-WORLD USE`. Never invent legal requirements; if unsure, leave a clearly marked `TODO(lawyer):` note.
17. The UI must never tell signers the card will be used "only" for an election. Cards may support a recognition demand or a petition.
18. The platform never files documents, contacts employers, or sends anything to the NLRB automatically. It generates drafts for humans.

### Engineering
19. TypeScript strict mode everywhere. No `any` without a comment explaining why.
20. Every feature ships with tests. The **plaintext-leak test** (Section 11) must pass on every commit.
21. Keep dependencies minimal. Justify any new dependency in the commit message.

---

## 3. Architecture summary (copy into CLAUDE.md)

- **Monorepo** (npm workspaces or pnpm):
  - `apps/web` — Vite + React + TypeScript + Tailwind CSS. Static build, mobile-first SPA. React Router.
  - `apps/api` — Node 20+ with Hono. REST JSON API. Serves the built SPA in production.
  - `packages/crypto` — all cryptographic logic, shared by web (and tests). Pure functions, fully unit tested.
  - `packages/shared` — shared types, zod schemas, constants.
  - `content/legal` — Markdown legal templates.
- **Database:** PostgreSQL 16, Drizzle ORM, SQL migrations checked in.
- **Email:** provider adapter interface with two implementations: `MailpitAdapter` (local dev) and `PostmarkAdapter` (production). Tracking disabled.
- **PDF generation:** `pdf-lib` in the browser. **ZIP:** `jszip` in the browser.
- **Local dev:** `docker compose up` starts Postgres and Mailpit. `npm run dev` runs web and api.
- **Deployment target:** a single Docker image deployed to Fly.io (or Render) with managed Postgres. Include a `Dockerfile` and `fly.toml`.
- **Testing:** Vitest (unit + API integration against a real test Postgres), Playwright (end-to-end, mobile viewport).

---

## 4. Threat model (for docs/THREAT_MODEL.md)

**Adversaries:**
- The employer (may try to learn who signed, infiltrate the campaign, or subpoena the platform).
- An attacker who compromises the server or database.
- A legal subpoena to the platform operator or its email provider.
- A single rogue or coerced trustee.

**What the design protects:**
- A full database dump or subpoena reveals: that some campaigns exist, how many cards each has, timestamps, and trustee public keys. It does **not** reveal employer names, union names, signer names, or any contact info (all encrypted client-side).
- No single trustee can decrypt cards (k-of-n threshold, k ≥ 2).
- The server never holds a decryption key.
- Invite links carry secrets only in the URL fragment.
- Infiltration through a forwarded group link is limited by in-person vouching.

**Known limitations (must be stated honestly on the public "How your data is protected" page):**
- At the moment a card is signed, the server briefly handles the signer's email address and card fields to send the legally required confirmation email. The email provider retains delivery logs (recipient address, timestamp) per its own policy.
- The hosting provider may log IP addresses at the network edge.
- A vouched member who is secretly hostile can see the card count.
- Anyone who can see a worker's phone or screen can see what they're doing. Advise: use a personal device on cellular data, never a work device or work Wi-Fi.
- Once cards are submitted to the NLRB or shown to the employer, names are no longer secret. The encryption protects the organizing period, not afterward.
- k trustees acting together can decrypt at any time, including before majority. The software cannot enforce the committee's policy on *when* to unlock; it only warns.
- The JavaScript is served by the platform. A compromised server could serve malicious JavaScript. Mitigations for later: published build hashes, open-source code, reproducible builds.

---

## 5. Cryptographic design

Use `libsodium-wrappers-sumo` (await `sodium.ready`) and `shamir-secret-sharing` (`split(secret, shares, threshold)` and `combine(shares)`, both async, operating on `Uint8Array`).

### 5.1 Keys

**Campaign key (`campaignKey`)** — 32 random bytes, generated in the creator's browser at campaign creation. Symmetric key used to encrypt campaign metadata (union name, employer name, unit description, estimated unit size, card text). Distributed to trustees and members **only via URL fragments and key files**, never sent to the server.

**Trustee keys** — each trustee generates in their own browser:
- a box keypair (`crypto_box_keypair`) for receiving sealed Shamir shares
- a signing keypair (`crypto_sign_keypair`) for authenticating privileged actions

Public keys are uploaded. Private keys never leave the trustee's device except inside their encrypted key file.

**Trustee key file** — JSON downloaded at enrollment:
```json
{
  "format": "trustee-keyfile-v1",
  "campaignId": "uuid",
  "trusteeIndex": 1,
  "kdf": { "alg": "argon2id13", "salt": "b64", "opslimit": "...", "memlimit": "..." },
  "nonce": "b64",
  "ciphertext": "b64"
}
```
The ciphertext is `crypto_aead_xchacha20poly1305_ietf_encrypt` of `{ boxSecretKey, signSecretKey, campaignKey }` under a key derived with `crypto_pwhash` (Argon2id, `OPSLIMIT_MODERATE`, `MEMLIMIT_MODERATE`) from a trustee-chosen passphrase (enforce a minimum of 4 random words or 14+ characters; offer a generated passphrase). Also offer to store the encrypted key file in IndexedDB on that device for convenience; it still requires the passphrase to unlock.

### 5.2 Encrypting a card (in the signer's browser)

1. Build the card payload (Section 6.4) as canonical JSON.
2. Generate a random 32-byte `cardKey`.
3. Encrypt the payload with XChaCha20-Poly1305 (`crypto_aead_xchacha20poly1305_ietf_encrypt`), random 24-byte nonce, associated data = `campaignId || cardTemplateVersion`.
4. `split(cardKey, n, k)` → n shares.
5. For trustee i, `crypto_box_seal(share_i, trusteeBoxPublicKey_i)`.
6. Send `{ ciphertext, nonce, sealedShares[], templateVersion }` to the server.
7. Zero out `cardKey` and shares in memory after use (`sodium.memzero`).

Result: no single trustee can open any card, and the server can open nothing.

### 5.3 Unlock ceremony (in one browser, with k trustees present)

1. The page fetches all non-withdrawn, vouched card ciphertexts and sealed shares for the campaign.
2. Trustee A loads their key file and enters their passphrase. The page decrypts A's private keys and opens A's sealed share for every card. Private keys are zeroed after use.
3. Repeat for trustees B, C, … until k trustees have contributed.
4. For each card, `combine(shares)` → `cardKey` → decrypt payload.
5. Everything stays in memory. The page generates the export package (Section 9) and offers a download. Nothing decrypted is sent to the server.
6. If fewer than k valid shares combine, or decryption fails, show a clear error naming which cards failed.
7. If vouched cards are below 50% of the estimated unit size, show a prominent warning before proceeding: "You are below majority. Unlocking now means names exist in readable form on this device. Continue?"

### 5.4 Trustee authentication

Privileged API calls (view exact admin data, create trustee invites, freeze, approve destroy) use challenge–response:
1. `POST /api/auth/challenge` → `{ challengeId, nonce }` (single-use, 2-minute expiry, held in memory).
2. Client signs `nonce || route || campaignId` with `crypto_sign_detached`.
3. Client sends `{ challengeId, trusteeIndex, signature }` with the request. Server verifies with the stored signing public key.

### 5.5 Member credentials

After signing, each signer receives a **member token** (32 random bytes, base64url). The server stores `SHA-256(token)`. The browser stores the token and campaign key in localStorage, and the UI shows a **member link** (`/m#t=<token>&k=<campaignKey>&c=<campaignId>`) with a strong prompt to save it privately (e.g., in a password manager or Signal "Note to Self").

---

## 6. Data model (Drizzle / Postgres)

All IDs are UUIDv4. All timestamps are `timestamptz`. No column may contain plaintext personal data.

### 6.1 `campaigns`
| column | type | notes |
|---|---|---|
| id | uuid pk | |
| status | enum `draft` \| `active` \| `frozen` | `draft` until all n trustees enrolled |
| threshold_k | int | 2 ≤ k ≤ n |
| trustee_count_n | int | 2 ≤ n ≤ 7 (UI defaults: 2-of-3, 3-of-5) |
| meta_ciphertext | bytea | encrypted campaign metadata |
| meta_nonce | bytea | |
| card_template_version | text | e.g. `card-v1` |
| created_at | timestamptz | |
| last_activity_at | timestamptz | updated on any card/invite activity |

### 6.2 `trustees`
| column | type | notes |
|---|---|---|
| id | uuid pk | |
| campaign_id | uuid fk | on delete cascade |
| trustee_index | int | 1..n, unique per campaign |
| enrollment_token_hash | bytea | nullable after enrollment |
| box_public_key | bytea | nullable until enrolled |
| sign_public_key | bytea | nullable until enrolled |
| enrolled_at | timestamptz | |

Trustee display names (e.g. "Maria") are stored **inside** the encrypted campaign metadata, not here.

### 6.3 `invites`
| column | type | notes |
|---|---|---|
| id | uuid pk | |
| campaign_id | uuid fk | cascade |
| token_hash | bytea unique | |
| kind | enum `direct` \| `group` | direct = single-use, auto-vouched; group = multi-use, requires vouching |
| created_by_card_id | uuid fk nullable | the member who created it (null if created by a trustee before signing) |
| created_by_trustee_index | int nullable | |
| max_uses | int | 1 for direct; default 50 for group |
| use_count | int | |
| expires_at | timestamptz | direct: 7 days; group: 72 hours (configurable) |
| revoked_at | timestamptz nullable | |

### 6.4 `cards`
| column | type | notes |
|---|---|---|
| id | uuid pk | |
| campaign_id | uuid fk | cascade |
| invite_id | uuid fk | |
| ciphertext | bytea | |
| nonce | bytea | |
| sealed_shares | jsonb | array of `{ trusteeIndex, sealed: b64 }` |
| template_version | text | |
| status | enum `pending` \| `vouched` | withdrawn cards are hard-deleted, not flagged |
| vouch_code_hash | bytea nullable | set for group-link cards |
| vouch_attempts | int | lock after 5 failures |
| member_token_hash | bytea unique | |
| confirmation_sent_at | timestamptz nullable | |
| confirmation_message_id | text nullable | provider's ID only |
| disavow_token_hash | bytea | from the confirmation email link |
| disavowed_at | timestamptz nullable | |
| created_at | timestamptz | **authoritative signature date** (server time) |

**Card payload (encrypted, never stored in plaintext):**
```ts
type CardPayload = {
  legalName: string;          // required
  personalEmail: string;      // required, validated
  phone: string;              // required, E.164 normalized
  employerName: string;       // required, copied from campaign metadata
  unionName: string;          // required, copied from campaign metadata
  cardText: string;           // exact text shown to the signer
  cardTextSha256: string;     // hex hash of cardText
  typedSignature: string;     // must match legalName (case-insensitive, trimmed)
  consentChecked: true;
  clientSignedAt: string;     // ISO, informational; server created_at is authoritative
  jobTitle?: string;          // optional
  shiftOrDepartment?: string; // optional
  preferredLanguage?: string; // optional
};
```

### 6.5 `destroy_approvals`
| column | type | notes |
|---|---|---|
| campaign_id | uuid fk | cascade |
| trustee_index | int | |
| approved_at | timestamptz | |
| primary key | (campaign_id, trustee_index) | |

**Campaign metadata payload (encrypted with campaignKey):**
```ts
type CampaignMeta = {
  unionName: string;
  employerName: string;
  employerAddress?: string;
  unitDescription: string;       // e.g. "All baristas and shift leads at the Main St location"
  estimatedUnitSize: number;
  trusteeNames: { index: number; displayName: string }[];
  cardText: string;              // rendered from template with union + employer names
  createdAt: string;
};
```

---

## 7. User flows and screens

Mobile-first. Every screen must work well on a 375px-wide phone.

### 7.1 Public pages
- **Home** — plain-language explanation: what this is, who it's for, how it protects people, "Start a campaign" button. Clear statement: "This is a tool. It is not a union and not a law firm."
- **How your data is protected** — honest, specific: what the server sees, what it can't see, known limitations from Section 4.
- **Your rights (basics)** — Section 7 of the NLRA protects workers acting together; illegal for employers to retaliate or interrogate; who is *not* covered (supervisors, independent contractors, agricultural and domestic workers, public-sector employees under federal law, rail/airline workers under the RLA). Link to nlrb.gov. From `/content/legal/rights.md`.
- **Safety tips** — personal device, cellular data, don't use work email/Slack/computers, don't sign while on the clock, talk in person.
- **Terms** and **Privacy** — drafts from `/content/legal/`.

### 7.2 Create campaign (`/start`)
Wizard, one question per screen:
1. Union name (with examples; explain they can name their own independent union).
2. Employer's legal name (with help text: "check your paystub or W-2") and optional address.
3. Who's in the group? Free-text unit description with guidance: people who share similar jobs, skills, supervision, and location usually belong together.
4. Estimated number of people in that group.
5. Trustees: how many (3 or 5 recommended), threshold (auto-suggest majority of trustees, min 2), and each trustee's first name or nickname.
6. Review the rendered card text.
7. Creator's browser generates `campaignKey`, encrypts metadata, creates campaign (status `draft`), and receives n **trustee enrollment links** (`/t#e=<enrollToken>&k=<campaignKey>&c=<campaignId>`). Show each with a native share button (Web Share API, fallback to copy). The creator is trustee #1 and enrolls immediately.

### 7.3 Trustee enrollment (`/t#...`)
Explain the trustee role in plain language: "You hold one of n keys. Any k of you together can open the cards. Nobody can do it alone — including this website." Generate keys, choose/generate passphrase, download key file (force the download and a checkbox "I saved my key file and passphrase"), upload public keys. When all n trustees are enrolled, the campaign becomes `active`.

### 7.4 Inviting
From the member or trustee dashboard:
- **Invite one person** → direct link (single-use, auto-vouched). Share via Web Share API.
- **Create a group link** → multi-use, expires in 72h, requires vouching. Show a warning: "Anyone who gets this link can sign, but their card won't count until you confirm them in person."
- Invite URL format: `/j#i=<inviteToken>&k=<campaignKey>&c=<campaignId>`.
- **No server-side bulk SMS/email sender in the MVP.** Instead, provide a "Prepare messages" helper that generates a suggested message text the organizer copies into their own messaging app.

### 7.5 Signing (`/j#...`)
1. Landing screen decrypts campaign metadata locally and shows: union name, employer, a one-paragraph explanation, safety tips, and "Read the card."
2. **Card screen:** exact card text in a bordered "card" visual. Fields: legal name, personal email, mobile phone, optional job title / shift / department. Typed signature field ("Type your full name to sign") and consent checkbox. A plain statement: "Your information is encrypted on your phone before it's sent. This website cannot read it."
3. On submit: encrypt (Section 5.2), POST the card, then POST to the confirmation endpoint.
4. **Done screen:**
   - Direct invite: "Your card is signed and counted."
   - Group link: show the **two-word vouch code** in large type: "Tell this code, in person, to the coworker who invited you: **MAPLE-RIVER**. Your card counts once they enter it."
   - Show the member link with save instructions.
   - What happens next, and rights reminder.

### 7.6 Confirmation Transmission (email)
Sent immediately after the card is stored. Subject: "Confirmation: you signed a union authorization card." Body restates: legal name, email, phone, the full card text, the date signed (server `created_at`), and employer name. Include:
- "If you did not sign this card, click here:" → disavow link `/d#t=<disavowToken>&c=<cardId>` which, after a confirmation click, sets `disavowed_at`.
- "Reply to this email if anything is wrong." Replies go to a configurable inbox address (`CONFIRMATION_REPLY_TO`); document that committees must monitor it and provide any responses to the NLRB.
- No tracking pixels, no rewritten links.

### 7.7 Member dashboard (`/m#...`)
- Vouched members see: vouched card count, pending count, progress bar vs. estimated unit size with markers at 30%, 50%+1, and 70%. Plain explanations of each marker.
- Pending members see only: "Your card is waiting to be confirmed by the coworker who invited you."
- Vouched members can create invites and see their **pending vouch queue** for group links they created (listed as "Signer #7 — 2 hours ago", never names), with a field to enter the code they heard in person.
- "Withdraw my card" → confirmation dialog → hard delete.

### 7.8 Trustee dashboard (`/t/dashboard`, key file + passphrase unlock)
Everything a member sees, plus: invites overview, revoke group links, freeze campaign (any single trustee; stops new signatures), approve destroy (needs k approvals), and **Unlock & export**.

### 7.9 Unlock & export (`/t/unlock`)
Ceremony UI per Section 5.3. Big, clear steps: "Trustee 1 of 3: load your key file," etc. Show a summary after decryption: total cards, disavowed cards (flagged, excluded by default), cards with missing confirmation, duplicates by email or phone (flag for human review, don't auto-remove). Then generate the package.

---

## 8. API endpoints (Hono)

All request/response bodies validated with zod. All error responses are generic (`{ error: "code" }`), never echo input.

| method | route | auth | purpose |
|---|---|---|---|
| POST | /api/campaigns | none (rate-limited) | create draft campaign; returns campaignId + trustee enrollment tokens |
| GET | /api/campaigns/:id/meta | invite, member, or trustee token | returns encrypted metadata + trustee public keys + k/n + status |
| POST | /api/trustees/enroll | enrollment token | upload public keys |
| POST | /api/auth/challenge | none | trustee challenge nonce |
| POST | /api/invites | member token (vouched) or trustee signature | create invite |
| POST | /api/invites/:id/revoke | creator or trustee | revoke |
| POST | /api/invites/resolve | invite token in body | validate invite, return campaignId + kind |
| POST | /api/cards | invite token in body | store encrypted card; returns cardId, memberToken, vouchCode (if group), disavowToken |
| POST | /api/cards/:id/confirm | member token | send Confirmation Transmission; persist nothing but sent_at + message id |
| POST | /api/cards/:id/vouch | member token of invite creator, or trustee | submit vouch code |
| DELETE | /api/cards/me | member token | withdraw own card (hard delete) |
| POST | /api/cards/disavow | disavow token | mark disavowed |
| GET | /api/campaigns/:id/progress | vouched member or trustee | counts only |
| GET | /api/campaigns/:id/pending-vouches | member token | pending cards from invites this member created (ids + timestamps only) |
| GET | /api/campaigns/:id/export-bundle | trustee signature | all vouched card ciphertexts + sealed shares + created_at + confirmation/disavow status |
| POST | /api/campaigns/:id/freeze | trustee signature | freeze |
| POST | /api/campaigns/:id/destroy-approve | trustee signature | record approval; on k approvals, hard-delete campaign and all rows |

Tokens are always sent in the request body or an `Authorization: Bearer` header — never in the URL.

---

## 9. Export package (generated entirely in the browser)

A ZIP named `<union-name>-cards-<YYYY-MM-DD>.zip` containing:

1. `roster.csv` — one row per card: legal name, email, phone, employer, union, date signed (server timestamp), job title, shift/department, confirmation sent timestamp, disavowed (yes/no), flags (duplicate email/phone). Disavowed cards excluded by default with a toggle to include them for review.
2. `cards/<NNN>-<last-name>.pdf` — one PDF per card showing the exact card text, all fields, the typed signature, the server timestamp, the card template version, and `cardTextSha256`.
3. `declaration-DRAFT.pdf` and `.md` — declaration per GC Memo 15-08, rendered from `/content/legal/declaration.md`, describing: the website-based electronic signature method; that signers entered their own contact information; that a Confirmation Transmission was sent to each signer's provided email immediately after signing; that card contents were encrypted on the signer's device and could not be altered without detection (authenticated encryption); and that the exported contents are the same text signers saw (template version + SHA-256). Leave blanks for the declarant's name, title, signature, and date.
4. `confirmations-log.csv` — card number, confirmation sent timestamp, provider message ID, disavowed timestamp.
5. `recognition-demand-letter-DRAFT.md` — from template: identifies the union, the unit, states a majority has authorized the union, requests voluntary recognition, and offers verification of cards by a mutually agreed neutral third party (do **not** attach the roster to the letter by default).
6. `form-502-prefilled.pdf` — the official NLRB Form 502 (RC petition) with fields pre-filled from campaign metadata and counts. See Section 10.
7. `NEXT-STEPS.md` — checklist from `/content/legal/next-steps.md`: choose recognition demand vs. election petition; that the showing of interest is filed with the NLRB but is **not** served on the employer; serve the petition on the employer as the NLRB requires (verify current requirements at nlrb.gov "Steps for filing a petition"); e-file via MyNLRB; keep monitoring the confirmation reply inbox and provide responses to the NLRB; talk to a labor attorney or experienced organizer before filing.

Every generated document carries a footer: `DRAFT — review with a labor attorney before filing or sending.`

---

## 10. Form 502 handling

1. Download the current official Form NLRB-502 (RC) PDF from nlrb.gov into `apps/web/public/forms/`. Record the source URL and download date in `docs/FORMS.md`.
2. Write a script `scripts/inspect-form.ts` that uses pdf-lib to list all AcroForm field names and types. Run it and commit the output to `docs/FORMS.md`.
3. Map fields you can confidently fill (employer name/address, union name, unit description, approximate number of employees, petition type RC). Leave everything else blank for humans.
4. If the PDF is not fillable or fields can't be mapped reliably, generate a separate `form-502-worksheet.pdf` listing each form box number and the value to enter, and include the blank official form. Tell me which path you took.

---

## 11. Testing requirements

### Unit (Vitest)
- `packages/crypto`: keypair generation; key file encrypt/decrypt round-trip; wrong passphrase fails; card encrypt → unlock with exactly k trustees succeeds; k−1 fails; wrong trustee key fails; tampered ciphertext, nonce, or associated data fails; metadata encrypt/decrypt; memzero called on sensitive buffers.
- Card payload validation (zod): missing required fields rejected; DOB/SSN-like patterns in optional fields rejected with a friendly message.

### API integration (Vitest + test Postgres)
- Full lifecycle: create campaign → enroll trustees → invites → cards → vouch → export bundle → destroy.
- Direct invite can't be reused. Expired or revoked invites rejected. Group link respects max_uses.
- Vouch code: correct code vouches; 5 wrong attempts locks.
- Only the invite creator (or a trustee) can vouch cards from that invite.
- Pending members can't see progress.
- Trustee signature auth: valid passes; replayed challenge fails; wrong key fails.
- Destroy needs k approvals, then all rows for the campaign are gone.

### Plaintext-leak test (must pass on every commit)
Run the full lifecycle with distinctive fake values (e.g. `Zyxwvut Qqqname`, `leaktest+unique@example.com`, `+15550199999`, employer `Leakcheck Industries LLC`, union `Leakcheck Workers United`). Then:
1. `pg_dump` the test database and assert none of those strings (or their lowercase/uppercase forms) appear.
2. Capture all API log output during the run and assert none appear.
3. Assert no invite, member, or disavow token appears in logs.

### End-to-end (Playwright, mobile viewport)
Create a 2-of-3 campaign, enroll all trustees, sign 4 cards (2 direct, 2 via group link), vouch one group card, withdraw one card, disavow one card, run the unlock ceremony with 2 trustees, download the ZIP, and assert its contents (roster rows, PDFs present, disavowed card flagged/excluded). Also assert that with 1 trustee the unlock cannot complete.

### Security checks in CI
- Assert CSP and security headers on `/` and an API route.
- Assert the built SPA contains no references to external origins (grep build output for `http://` / `https://` outside an allowlist of documentation links).
- `npm audit --audit-level=high` passes.

---

## 12. Build phases

Stop after each phase for my review.

**Phase 0 — Scaffold.** Monorepo, TypeScript strict, ESLint + Prettier, Vite/React/Tailwind web app, Hono API, Drizzle + migrations, docker compose (Postgres 16 + Mailpit), structured allowlist logger, security headers + CSP middleware, Vitest + Playwright configured, GitHub Actions CI running lint + tests. CLAUDE.md, docs/SPEC.md, docs/THREAT_MODEL.md. A placeholder home page. *Done when:* `docker compose up && npm run dev` works, CI passes, header tests pass.

**Phase 1 — Crypto package.** Everything in Section 5 as pure, tested functions. *Done when:* all crypto unit tests pass, including negative tests.

**Phase 2 — Campaigns and trustees.** Create-campaign wizard, encrypted metadata, trustee enrollment, key file download, campaign activation, trustee challenge–response auth. *Done when:* a 3-of-5 campaign can be created and fully enrolled in the browser.

**Phase 3 — Invites and signing.** Direct and group invites, Web Share API, signing flow, client-side card encryption, card storage, member token and member link, Confirmation Transmission via Mailpit, disavow link. *Done when:* a card can be signed via each invite type and the confirmation email appears in Mailpit with all required fields.

**Phase 4 — Vouching and dashboards.** Vouch codes, pending queues, progress dashboard with threshold markers, withdraw card, trustee dashboard, freeze, revoke. *Done when:* the group-link vouching flow works end to end.

**Phase 5 — Unlock and export.** Unlock ceremony, local decryption, duplicate/disavow flags, ZIP with roster, PDFs, declaration, confirmations log, demand letter, Form 502 handling, next-steps checklist. *Done when:* the E2E test in Section 11 passes.

**Phase 6 — Lifecycle and safety.** Destroy with k approvals, auto-expiry job (hard-delete campaigns with no activity for 180 days, configurable; warn trustees in-app at 150 days), rate limiting, generic errors, plaintext-leak test. *Done when:* all Section 11 tests pass.

**Phase 7 — Public pages and polish.** Home, How your data is protected, Your rights, Safety tips, Terms, Privacy (all from `/content/legal/` drafts). Accessibility pass (WCAG 2.1 AA: labels, contrast, focus states, keyboard nav). Loading and error states everywhere. *Done when:* Lighthouse accessibility ≥ 95 on key pages.

**Phase 8 — Deployment and review.** Dockerfile, fly.toml, production env docs, Postmark adapter with tracking disabled, `docs/DEPLOY.md`, `docs/SECURITY_REVIEW.md` (walk through each rule in Section 2 and show how the code satisfies it, and list anything you're unsure about). *Done when:* the app deploys and the full flow works on a staging URL.

---

## 13. Design direction

The app must feel **calm, trustworthy, and official** — closer to a well-made government service or a credit union than a startup or a crypto app.

- **Tone:** plain language, 6th–8th grade reading level, warm and steady. Never hype. Never "hacker" aesthetics, dark neon, or blockchain imagery.
- **Type:** one self-hosted, highly legible sans-serif (e.g. Inter or Source Sans 3 via local font files). Body 17–18px on mobile. Generous line height.
- **Color:** off-white background, near-black text, one deep, confident accent (e.g. deep navy or forest green) for primary actions, and a restrained warm secondary for highlights. Red only for true warnings. All combinations meet WCAG AA contrast.
- **The card:** the authorization card should look like a real, dignified card — bordered, with the union name at the top, the card text in readable type, and the signature line clearly marked. This moment should feel serious and respected.
- **Layout:** single column on mobile, max ~640px content width on desktop. Big tap targets (min 44px). One primary action per screen.
- **Progress:** the progress bar is the emotional center of the dashboard. Clear markers and short captions ("30% — enough to ask the NLRB for an election").
- **Trust signals:** a short, persistent line near every form: "Encrypted on your device. This site can't read it." with a link to the data-protection page. No stock photos. Simple line icons only, self-hosted (e.g. Lucide as local SVGs).
- **Language:** English for MVP, but put every UI string in a locale file (`apps/web/src/locales/en.json`) so Spanish can be added next.

---

## 14. Legal content drafts to create in `/content/legal/`

Create each as a Markdown draft with the required review header (rule 16). Keep them plain and short.

- `card-v1.md` — authorization card text. Suggested: *"I, the undersigned employee of {{employerName}}, authorize {{unionName}} to represent me for the purpose of collective bargaining with my employer regarding wages, hours, and other terms and conditions of employment."* Add a short, non-misleading note that the card may be used to request voluntary recognition or to support a petition for an NLRB election.
- `declaration.md` — GC Memo 15-08 declaration draft (Section 9, item 3).
- `recognition-demand-letter.md` — Section 9, item 5.
- `next-steps.md` — Section 9, item 7.
- `rights.md`, `safety.md`, `terms.md`, `privacy.md`, `data-protection.md`.

Every one of these must say it is a draft requiring attorney review.

---

## 15. Explicitly out of scope for the MVP

Do not build these, even if they seem helpful:
- Blockchain, smart contracts, zero-knowledge proofs, or email-DKIM verification.
- Automatic filing with the NLRB, automatic sending of demand letters, or automatic unfair-labor-practice charges.
- Server-side bulk SMS or email invite sending.
- Payments, dues, bylaws, voting, grievance tracking (planned for v2).
- Native mobile apps.
- Any analytics, telemetry, or error-tracking service that receives request data.
- Any AI features that send worker data to third parties.

---

## 16. Environment variables

```
DATABASE_URL=
APP_BASE_URL=
EMAIL_PROVIDER=mailpit|postmark
POSTMARK_SERVER_TOKEN=
EMAIL_FROM=
CONFIRMATION_REPLY_TO=
CAMPAIGN_INACTIVITY_DAYS=180
GROUP_INVITE_TTL_HOURS=72
DIRECT_INVITE_TTL_DAYS=7
APP_NAME=
```

---

Begin with Section 0, then Phase 0. Stop and report when Phase 0 is complete.

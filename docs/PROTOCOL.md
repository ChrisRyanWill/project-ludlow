# Project Ludlow protocols

Written so anyone can audit them, or build a compatible client. Everything below is implemented in `shared/crypto.js` and exercised by `test/unit.test.js`. Only libsodium (`libsodium-wrappers-sumo`) and Shamir secret sharing (`shamir-secret-sharing`) are used.

Encoding: base64url without padding everywhere. `aead` = XChaCha20-Poly1305 IETF with a random 24 byte nonce. `seal` = `crypto_box_seal`. `H` = SHA-256.

## 1. Zero-knowledge authorization cards

**Roles.** A campaign has `n` trustees and a threshold `k` (2 ≤ k ≤ n ≤ 7). Each trustee has a box keypair and a signing keypair, generated in their browser. The server holds only public keys.

**Campaign metadata** (union, employer, unit, trustee names, jurisdiction) is `aead(campaignKey, json, aad = "meta|" + campaignId)`. `campaignKey` is 32 random bytes made by the creator and shared only in URL fragments; the server never sees it.

**Signing a card.** In the signer's browser:
1. `payload` = canonical JSON of the card (name, email, phone, employer, union, exact card text, its SHA-256, typed signature, consent, client time, optional fields).
2. `cardKey` = 32 random bytes. `ciphertext = aead(cardKey, payload, aad = campaignId + "|" + templateVersion)`.
3. `shares = shamir.split(cardKey, n, k)`. For trustee *i*: `sealed_i = seal(share_i, trusteePublicBoxKey_i)`.
4. Send `{ciphertext, nonce, sealedShares[], templateVersion}`. Wipe `cardKey` and shares.

**Starting alone (founder-first).** Trustee 1 (the founder) can make their key and start collecting cards before anyone else has joined. Until the founder has signed the roster of the whole committee (section 1a), a card is sealed to the founder only: `cardKey` is sealed directly with `seal(cardKey, founderBoxKey)` and `sealMode = "solo"`. Once the roster is signed, the founder runs a *reshare*: for each solo card, open the sealed key, `shamir.split(cardKey, n, k)`, seal a share to each seat **of the signed roster**, **verify that k shares rebuild the key**, then upload; the server replaces the card's shares and marks it `shamir`. Only trustee 1 may do this (anyone else could only destroy cards), and the reshare bundle carries no ciphertext. A signer whose browser used a stale view (the roster was signed while they typed) gets `409 committee_changed`, checks the committee again, and re-seals.

**1a. Authenticating the trustees' keys.** Browsers seal to public keys the server hands them, so a server could hand out keys of its own and read whatever is sealed to them, with the genuine JavaScript. The server is therefore never trusted for *which* keys are real. Two things carry that trust instead, and neither passes through the server:

- **The founder's key check.** `founderCommit(boxPk, signPk) = base64url(H("ludlow founder v1|" + boxPk + "|" + signPk)[0..16])`: 128 bits over both of trustee 1's public keys. Every invitation link carries it as the `f` parameter, in the URL fragment the server never sees: trustee invitations, signing invitations and member links. Whoever makes an invitation puts it in: the founder works it out from their own keys, another trustee's key file holds the one from their own invitation, and a member's browser keeps the one from their own link. A link without one is refused.
- **The signed roster.** When every trustee has joined, and the founder has checked each trustee's key words with them in person, the founder signs `roster = {campaignId, k, n, seats: [{index: 1..n, boxPublicKey}]}` as `sign(founderSignKey, "ludlow roster v1|" + canonicalJson(roster))` and uploads it (`POST /api/campaigns/:id/roster`, founder only). The server checks it against the committee it holds, stores it, and from then on accepts only k-of-n cards. It cannot forge one: it has no signing key the browsers trust. Only those fields are signed, in a domain of their own, so a sign-in or a tally signature can never be a roster.

A browser decides what to seal to with `authenticate(meta, founderCheck, campaignId)` in `shared/roster.js`:
1. The link must carry a founder check and the founder must have enrolled.
2. `founderCommit` of the founder's keys **as the server lists them** must equal the link's check, or the browser refuses (`founder_mismatch`) before asking the person for anything.
3. With no roster: seal to the founder alone. Trustees who have enrolled but whom the founder has not signed for are not used, so a server that withholds the roster can only make cards sealed to the founder alone, never to a key of its own.
4. With a roster: it must verify under the founder's signing key, name this campaign, hold the founder's box key in seat 1, and agree with the server's own list of `n`, `k` and keys; otherwise the browser refuses (`roster_invalid`, `roster_mismatch`). Then it splits k-of-n among the roster's seats, not the server's list.

Everything that is sealed for the trustees goes through this: a signer's card, a member's report to the committee, and the founder's own re-lock of early cards (which uses the seats they signed). Each trustee's dashboard also checks that the founder's signature holds and that their own key is in their seat.

What this does **not** do: it makes the founder the anchor of trust (a founder who signs a roster with a rogue key in a seat has betrayed the people the design protects, and only the key-words check at the moment of signing catches it); it trusts whoever handed a person their link to have handed them the right one (the signing page shows the founder's key words, so a signer can compare them with the founder); it does not cover the workspace (grievances, steward keys, the election committee and vote keys); and it does not stop a server that serves malicious JavaScript.

**The release lock.** The campaign has `release_min`, a count chosen at creation. `GET /export-bundle`, the only route that returns card ciphertext, answers `403 threshold_not_met {have, need}` unless `have = |vouched cards not disavowed| >= need`. Raising `release_min` needs one trustee; lowering it needs `k` distinct trustees to approve the same value (approvals are cleared when applied). The number is shown to signers and members. This is server-enforced policy, not cryptography: see the threat model for what it does and does not stop.

**Opening.** In one browser, `k` trustees each unlock their key file (Argon2id moderate + aead) and open their sealed share for every card; `shamir.combine` yields `cardKey`; decrypt. Fewer than `k` shares produce garbage that fails authentication. Tampering with the ciphertext, nonce, campaign id or template version fails authentication.

**Key file** `trustee-keyfile-v1`: `{format, campaignId, trusteeIndex, kdf:{alg:"argon2id13", salt, opslimit, memlimit}, nonce, ciphertext}`. The plaintext is `{boxPublicKey, boxSecretKey, signPublicKey, signSecretKey, campaignKey, founder}` (`founder` is the founder's key check, which the trustee puts in the invitations they make); the AAD binds `format` and the header, so a file cannot be moved to another trustee or campaign.

**Authentication.** No passwords. Tokens are 32 random bytes made client-side; the server stores `H(token)`. Trustee actions use challenge-response: `POST /api/auth/challenge` returns a single-use, 2-minute `{challengeId, nonce}`; the client signs `nonce|route|scope` (route is the action, e.g. `POST /api/campaigns/:id/freeze`; scope is the campaign id) with `crypto_sign_detached`.

**Member identity.** A member's link carries a 32 byte `secret`. `authToken = kdf(secret, id 1)` is what the server sees (hashed). `lockerKey = kdf(secret, id 2)` never leaves the device and encrypts the member's private record. The server cannot derive one from the other.

**Vouching.** Cards from group links are pending until the link's creator submits the two-word code the signer was shown. The server stores `H("vouch|" + cardId + "|" + code)` and locks after 5 wrong tries.

**Reports** shared with the committee: `aead(reportKey, json)`, with `reportKey` sealed separately to the founder alone until the roster is signed and to every trustee in it after, and no link to the card.

## 2. Verifiable secret ballots (workspace)

1. The browser of whoever opens the vote generates a fresh box keypair, splits the *secret key* `k`-of-`m` among the election committee (Shamir), seals each share to a member's box key, wipes the secret key and the shares, and uploads the public key and sealed shares. The whole secret key is never stored or sent anywhere, but it does exist, for a moment, in that one browser: a person who opens a vote with modified code could keep it. Generating the key jointly with the committee is an open item ([#37](https://github.com/ChrisRyanWill/project-ludlow/issues/37)).
2. A voter's browser makes `plain = [option] + 31 random bytes`, `ciphertext = seal(plain, votePublicKey)` (fixed 107 characters), and a random 16 character receipt code. One transaction marks the voter as having voted and stores `{id (random), vote_id, ciphertext}` with **no voter reference and no timestamp**. The receipt hash `H("receipt|" + code)` goes in a separate, unlinked table. Ballots are stored in random-id order (`WITHOUT ROWID`), and every cast rewrites that vote's ballots and receipts in a fresh random order (`secure_delete` zeroes the old layout), so the file does not keep the order people voted in.
3. After closing, `k` committee members combine shares in one browser, decrypt, and count. If they publish the key, the server independently recounts and rejects a wrong tally, and **every member's browser can recount** and check that their receipt is in the list. Ballots are anonymous, so publishing the key reveals counts, never voters. If they do not publish the key, the server cannot recount, so it accepts the counts only when `k` different committee members have each signed exactly those counts for this vote: `sign(memberSignKey, "ludlow tally v1|" + voteId + "|" + counts.join(","))` (`signTally`).
4. A vote may carry an *effect* (dues, a bylaws change, removing a role) that the server applies itself when the vote passes. Such a vote is only ever counted with the key published (`409 key_required` otherwise), so everyone can recount the decision.

Known limit: a server operator watching traffic in real time could try to correlate a request with a ballot insertion. Timestamps and ordering are not stored, but perfect unlinkability against the operator is out of scope.

## 3. Tamper-evident books

Ledger and audit entries form hash chains: `hash_i = H(hash_{i-1} + "|" + canonicalJson(fields_i))`, starting from `GENESIS`. The ledger commits to private text (payee, memo) with `H(salt|payee|memo)`, so members can verify the chain without seeing what is private. Entries are immutable at the database level (triggers). Members' browsers re-derive every hash, and each device pins the newest entry it has seen, so history that is rewritten later is detected the next time anyone looks.

## 4. Software fingerprint

`npm run build` prints and stores `SHA-256(app.js)` in `build.json`. **Builds are designed to be reproducible**: a local build and the Docker build produced byte-identical output when last checked (this has not been re-checked since the latest security changes), so anyone can rebuild from the source and compare. The `/verify` page shows the fingerprint of the code actually running, and trustees compare it with each other and the published release before opening cards. This cannot catch a server that serves different code to different visitors; that is the main reason the server is meant to be self-hostable.

## 5. Diagrams

These show the same flows as the text above, in order. `S` is the server. Anything after `#` in a link is the URL fragment, which browsers never send to the server.

### 5.1 Starting alone, then locking the committee

```mermaid
sequenceDiagram
    autonumber
    participant F as Founder (trustee 1) browser
    participant S as Server
    participant T as Trustee i browser
    F->>S: POST /api/campaigns (k, n, release number, encrypted meta; campaignKey stays in the browser)
    F->>F: open own link: make box + sign keys, f = founderCommit(keys)
    F->>S: POST /api/trustees/enroll (seat 1 public keys)
    Note over F,S: Cards are sealed to the founder alone ("solo") until the roster is stored
    F-->>T: trustee link from the dashboard /t#...&f=... (in person or a private channel)
    T->>S: GET /api/campaigns/:id/meta
    T->>T: founderCommit(seat 1 keys from S) == f ? else refuse
    T->>T: make own keys; key file (Argon2id) keeps f
    T->>S: POST /api/trustees/enroll (public keys)
    F->>T: read key words aloud, in person, for every seat
    F->>F: rosterToSign(meta): {campaignId, k, n, seats}
    F->>S: POST /api/campaigns/:id/roster (signature by founder's sign key)
    S->>S: must equal its own committee, verify signature, store; now only k-of-n cards
    F->>S: GET /api/campaigns/:id/reshare-bundle (sealed keys, no ciphertext)
    F->>F: open each solo key, split k-of-n to the signed seats, check k rebuild it
    F->>S: POST /api/campaigns/:id/reshare
```

### 5.2 Signing a card

```mermaid
sequenceDiagram
    autonumber
    participant W as Signer browser
    participant S as Server
    W->>S: POST /api/invites/resolve (token hash from the link)
    W->>S: GET /api/campaigns/:id/meta (trustees, roster if signed)
    W->>W: authenticate(meta, f from link): founder only, or the signed seats; else refuse before asking anything
    W->>W: payload -> aead(cardKey); cardKey -> solo seal, or Shamir k-of-n sealed to each seat
    W->>S: POST /api/cards {ciphertext, nonce, sealed shares or solo key}
    alt the roster changed while the person was typing
        S-->>W: 409 committee_changed
        W->>S: GET /api/campaigns/:id/meta
        W->>W: authenticate again, re-seal, resend
    end
    S-->>W: stored (ciphertext only); confirmation email sent and the details discarded
```

### 5.3 Opening the cards

```mermaid
sequenceDiagram
    autonumber
    participant K as k trustees, one browser
    participant S as Server
    K->>S: GET /api/campaigns/:id/export-bundle (signed challenge)
    alt vouched cards < release number
        S-->>K: 403 threshold_not_met {have, need}
    else enough
        S-->>K: ciphertexts + sealed shares
        K->>K: each trustee unlocks their key file and opens their shares
        K->>K: shamir.combine (k shares) -> cardKey -> decrypt; filing package built in the browser
    end
```

### 5.4 A secret ballot

```mermaid
sequenceDiagram
    autonumber
    participant O as Browser of whoever opens the vote
    participant S as Server
    participant V as Voter browser
    participant C as k committee members, one browser
    O->>O: vote keypair; split secret key k-of-m; seal shares to committee box keys; wipe
    O->>S: POST /api/ws/votes (public key, sealed shares)
    V->>V: seal([option] + 31 random bytes) to the vote key; receipt code
    V->>S: POST /api/ws/votes/:id/ballot {ciphertext, H(receipt)}
    S->>S: one transaction: mark voted; store ballot and receipt apart, no voter, no time; rewrite rows in random order
    C->>S: GET /api/ws/votes/:id/tally-bundle (after it closes)
    C->>C: open shares, combine, decrypt, count
    alt key published (required for decisions with an effect)
        C->>S: POST /api/ws/votes/:id/results {secretKey, counts}
        S->>S: recount; refuse a wrong tally; apply the effect
        V->>S: GET /api/ws/votes/:id/ballots and /receipts; recount and find own receipt
    else key kept
        C->>S: POST /api/ws/votes/:id/results {counts, k signatures by committee members}
    end
```

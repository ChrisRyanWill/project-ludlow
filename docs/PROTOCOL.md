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

**Starting alone (founder-first).** Trustee 1 (the founder) can make their key and start collecting cards before anyone else has joined. While fewer than `n` trustees have enrolled, a card is sealed to the founder only: `cardKey` is sealed directly with `seal(cardKey, founderBoxKey)` and `sealMode = "solo"`. When the last trustee joins, the founder runs a *reshare*: for each solo card, open the sealed key, `shamir.split(cardKey, n, k)`, seal a share to each trustee, **verify that k shares rebuild the key**, then upload; the server replaces the card's shares and marks it `shamir`. Only trustee 1 may do this (anyone else could only destroy cards), and the reshare bundle carries no ciphertext. A signer whose browser used a stale view of the committee gets `409 committee_changed` and re-seals.

**The release lock.** The campaign has `release_min`, a count chosen at creation. `GET /export-bundle`, the only route that returns card ciphertext, answers `403 threshold_not_met {have, need}` unless `have = |vouched cards not disavowed| >= need`. Raising `release_min` needs one trustee; lowering it needs `k` distinct trustees to approve the same value (approvals are cleared when applied). The number is shown to signers and members. This is server-enforced policy, not cryptography: see the threat model for what it does and does not stop.

**Opening.** In one browser, `k` trustees each unlock their key file (Argon2id moderate + aead) and open their sealed share for every card; `shamir.combine` yields `cardKey`; decrypt. Fewer than `k` shares produce garbage that fails authentication. Tampering with the ciphertext, nonce, campaign id or template version fails authentication.

**Key file** `trustee-keyfile-v1`: `{format, campaignId, trusteeIndex, kdf:{alg:"argon2id13", salt, opslimit, memlimit}, nonce, ciphertext}`. The plaintext is `{boxPublicKey, boxSecretKey, signPublicKey, signSecretKey, campaignKey}`; the AAD binds `format` and the header, so a file cannot be moved to another trustee or campaign.

**Authentication.** No passwords. Tokens are 32 random bytes made client-side; the server stores `H(token)`. Trustee actions use challenge-response: `POST /api/auth/challenge` returns a single-use, 2-minute `{challengeId, nonce}`; the client signs `nonce|route|scope` (route is the action, e.g. `POST /api/campaigns/:id/freeze`; scope is the campaign id) with `crypto_sign_detached`.

**Member identity.** A member's link carries a 32 byte `secret`. `authToken = kdf(secret, id 1)` is what the server sees (hashed). `lockerKey = kdf(secret, id 2)` never leaves the device and encrypts the member's private record. The server cannot derive one from the other.

**Vouching.** Cards from group links are pending until the link's creator submits the two-word code the signer was shown. The server stores `H("vouch|" + cardId + "|" + code)` and locks after 5 wrong tries.

**Reports** shared with the committee: `aead(reportKey, json)`, with `reportKey` sealed separately to every trustee, and no link to the card.

## 2. Verifiable secret ballots (workspace)

1. The vote creator generates a fresh box keypair, splits the *secret key* `k`-of-`m` among the election committee (Shamir), seals each share to a member's box key, and uploads the public key and sealed shares. The whole secret key exists nowhere.
2. A voter's browser makes `plain = [option] + 31 random bytes`, `ciphertext = seal(plain, votePublicKey)` (fixed 107 characters), and a random 16 character receipt code. One transaction marks the voter as having voted and stores `{id (random), vote_id, ciphertext}` with **no voter reference and no timestamp**. The receipt hash `H("receipt|" + code)` goes in a separate, unlinked table. Ballots are stored in random-id order (`WITHOUT ROWID`).
3. After closing, `k` committee members combine shares in one browser, decrypt, and count. If they choose to publish the key, the server independently recounts and rejects a wrong tally, and **every member's browser can recount** and check that their receipt is in the list. Ballots are anonymous, so publishing the key reveals counts, never voters.
4. A vote may carry an *effect* (dues, a bylaws change, removing a role) that the server applies itself when the vote passes.

Known limit: a server operator watching traffic in real time could try to correlate a request with a ballot insertion. Timestamps and ordering are not stored, but perfect unlinkability against the operator is out of scope.

## 3. Tamper-evident books

Ledger and audit entries form hash chains: `hash_i = H(hash_{i-1} + "|" + canonicalJson(fields_i))`, starting from `GENESIS`. The ledger commits to private text (payee, memo) with `H(salt|payee|memo)`, so members can verify the chain without seeing what is private. Entries are immutable at the database level (triggers). Members' browsers re-derive every hash, and each device pins the newest entry it has seen, so history that is rewritten later is detected the next time anyone looks.

## 4. Software fingerprint

`npm run build` prints and stores `SHA-256(app.js)` in `build.json`. **Builds are reproducible**: a local build and the Docker build produce byte-identical output, so anyone can rebuild from the source and compare. The `/verify` page shows the fingerprint of the code actually running, and trustees compare it with each other and the published release before opening cards. This cannot catch a server that serves different code to different visitors; that is the main reason the server is meant to be self-hostable.

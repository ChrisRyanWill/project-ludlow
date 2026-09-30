# Ballot secrecy: what to promise, and what to build next

*Research note for [#39](https://github.com/ChrisRyanWill/project-ludlow/issues/39), 30 September 2026. It was written by an AI session; a cryptographer should check the reasoning before any of it is built. It changes no code.*

## 1. How voting works today (short)

1. **Opening a vote.** A browser makes a key pair for the vote, splits the secret key k-of-m among the election committee, and uploads the public key.
2. **Casting.**
   - A voter's browser seals a fixed-size ballot to that public key (`crypto_box_seal`) and makes a random receipt code.
   - One transaction marks the voter as having voted and stores the ballot and the receipt hash in two separate tables, with no member reference and no time.
   - Every cast rewrites that vote's rows in a random order.
3. **Counting.** k committee members rebuild the key in one browser and count. For a decision with an effect, the key must be published: the server recounts, and every member can too.

## 2. The three limits, and who they matter against

The unions this is for have 30 to 3,000 members. The adversaries who matter most are:

- **the employer**, directly or through a member it pressures;
- **a faction inside the union**;
- **the person running the server**, who may be a volunteer, or a host under legal pressure.

| Limit (from #39) | Who can use it | How bad, for these unions |
|---|---|---|
| **1. Ballots can be replaced by someone who writes the database**; receipts are not tied to ballots. | The server's operator, or someone with the database file | High for an operator who wants a result, but it takes deliberate fraud with access to the server. The count check already stops *adding* ballots. |
| **2. An operator running modified code can link a session to the ciphertext it sent**, then read it once the key is published (or with k committee keys). | The operator | **Highest.** This is exactly the employer-pressures-the-host case, and it defeats ballot secrecy completely. |
| **3. Once the key is published, a voter who kept their ciphertext can prove how they voted.** | A voter, and whoever pressures them (the employer, a faction) | **High for strike votes and contract ratification**, where coercion is real; low for routine questions. |

## 3. Techniques, measured against our constraints

The constraints:
- only libsodium and `shamir-secret-sharing`;
- no hand-written primitives (`CLAUDE.md` rule 9);
- everything runs in a phone browser;
- no trusted third party, one server.

| Technique | Fixes | Keeps "cannot prove your vote"? | Fit |
|---|---|---|---|
| **Anonymous submission channel.** The member gets a one-time *blind* token over their session, then later submits the ballot with the token and no session, over a fresh connection. | 2 (mostly) | Yes | **Good.** A blind signature over ristretto255 is possible with libsodium's group operations, but it is a protocol built on primitives and **needs a cryptographer's design and review**. Timing and IP address can still link the two steps. Batching submissions (the ballot is sent at a random later time) narrows that. |
| **Publish a list of ballot hashes at close; each voter checks their own ciphertext is in it.** | 1 (detects replacement of *your* ballot) | **No.** The ciphertext you kept becomes your proof once the key is published. | Cheap, but it makes limit 3 worse. |
| **Do not publish the key; count with k signatures only** (possible today for votes without an effect) | 3 | Yes | Already available. Loses the public recount, which is what stops a committee from lying. |
| **Re-encryption mix net** (shuffle and re-randomize ballots before counting, with proofs) | 1 and 3 | Yes | **Poor fit.** It needs ElGamal-style re-encryption and zero-knowledge shuffle proofs. Neither is in libsodium, and building them would break rule 9. |
| **Threshold homomorphic tally** (add up encrypted ballots, decrypt only the total) | 3 (only totals are ever decrypted) | Yes | **Poor fit** for the same reason. It also needs a proof per ballot that it is a valid choice. |
| **Benaloh cast-or-audit** (voter can challenge the device to show it encrypted correctly) | A lying *device*, not the server | Yes | Useful against altered JavaScript, which is outside the current threat model. Worth keeping in mind. |

## 4. Recommendation

**What to promise, in plain words, now** (the threat model and site already mostly say this):

- **Stored data:** ballots are secret from other members, officers and anyone with a copy of the database. Stored ballots carry no name and no time, and their order on disk is shuffled.
- **Adding ballots:** members can check the count, and a stuffed ballot box (more ballots than voters) is refused.
- **Honest operator:** with an honest operator running the published code, nobody learns how an individual voted.

**What to stop promising, or never start:**

- **Not** secrecy against the operator of the server. An operator who runs modified code can learn how individuals voted. Say this next to every secret-ballot claim that could be read as "even the server can't know".
- **Not** that a receipt proves your ballot was counted as cast. It proves only that a receipt was recorded.
- **Not** coercion resistance for votes whose key is published. The app should say so when the key is about to be published for a strike or ratification vote. That is a small UI change; see section 5.

**What to build, in order of value per effort:**

1. **Now (UI, no crypto):** when a committee is about to publish the key, say plainly that anyone who kept a copy of their ballot can then prove how they voted. Offer "count without publishing" for votes with no effect when coercion is a concern. This adds an honest choice and touches no protocol.
2. **Next (needs a cryptographer):** an anonymous submission channel: blind tokens over the session, then an unauthenticated, delayed ballot submission. It is the only proportionate step that addresses limit 2, the most serious one. Prototype it behind a flag and have it reviewed before any union relies on it.
3. **Later, if a reviewer finds a sound construction within the dependency rules:** a threshold tally, so the ballot key is never published and limit 3 disappears.
4. **Do not** add a public ballot-hash list with voter self-checks while the key is published. It trades coercion resistance for replacement detection, which is the wrong trade for strike votes.

## 5. Decision needed

- Whether the maintainer agrees with the promises in section 4. If so, the site and threat model need only small wording changes, and I can make them.
- Whether to pursue step 2, and with whom (#7, independent cryptographic review).

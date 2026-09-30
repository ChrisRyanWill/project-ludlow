# Internal security review, pass 1

*28 September 2026. AI-assisted. **Not an independent audit.***

This page is the honest record of the first security review of Project Ludlow: how it was done, what it found, what was fixed, and what is still open. It exists so that human reviewers ([issue #7](https://github.com/ChrisRyanWill/project-ludlow/issues/7)) can spend their time on the hard problems instead of rediscovering the easy ones, and so that nobody has to take our word for what the software does.

## Why this is not an audit

The same family of AI models wrote this code and reviewed it. That means blind spots are likely to be shared: a class of mistake the author does not see, the reviewer may not see either. The review was thorough by the standards of a first pass (it ran real attacks against throwaway servers and found serious problems), but **it does not replace an independent cryptographer, a security engineer, or a labor attorney.** Treat the "checked and sound" list below as "we looked and found nothing", not as a guarantee.

## Method

- **Four adversarial reviewers**, each given one slice of the code and told to find real, exploitable problems rather than style issues: (1) the cryptography and protocols, (2) the organizing ("campaign") server, (3) the union workspace server, (4) the browser client. Each read `CLAUDE.md`, the threat model and the protocol first, was **read-only** on the repository, and confirmed suspicions by running short scripts against throwaway in-process servers with temporary databases.
- **A hand review of the supply chain**: `npm audit` (0 vulnerabilities in runtime dependencies), workflow permissions (least privilege, no secrets, no `pull_request_target`), the Dockerfile.
- **Every claim was re-checked against the code** before anything was changed, and for each fix a **test was written first and confirmed to fail on the old code**. Some claims were narrowed on inspection (for example the reviewer's "quick exit contradicts the threat model" was true of the member card page but the threat model's "no persistent login" referred to workspace sessions; the "signed and confirmed" mismatch was a wording problem, because *confirmed* meant two different things).
- The tests added for these findings are named after the behavior they protect, so `npm test` is also the regression suite for this page.

## Findings and what happened to them

Severity is our judgement after checking, not the reviewer's label. "Ran" means a reviewer reproduced it on a throwaway server and we reproduced it again with a test.

### Fixed in this pass

| # | Severity | Finding | Reviewers' ids | Fix |
|---|---|---|---|---|
| R-01 | **Critical** | **Trustee seat takeover.** Any enrolled trustee could re-issue an empty seat, enroll a second key file into it, and hold *k* shares alone: open every card and approve lowering the release number *k* times. Ran (three reviewers). | web W1, campaign C1, crypto C2 | `POST /trustees/reset` is founder-only; the same keys cannot fill two seats; the founder checks each trustee's **key words** (10 words, about 77 bits) aloud before locking cards to the committee. |
| R-02 | **Critical** | **Made-up tally.** One election-committee member could post any counts without the ballot key, and the server applied the vote's effect (a recall, dues, bylaws). Ran. | ws WS-01, crypto C3 | A decision with an effect always needs the ballot key, so the server recounts it. A result without the key needs signatures over the same counts from *k* different committee members. |
| R-03 | High | **"No" could win as "passed".** `plurality` counted any unique winner as passed, and creators chose option order, so a recall where "Keep" won removed the role. Ran. | ws WS-02 | Effect votes have fixed options (option 0 is the action) and only majority or two-thirds rules. |
| R-04 | High | **Recall circumvention.** A recall's target could open it with a few seconds' window, close it at once, sit on its committee, or hand the role back afterwards. Ran. | ws WS-05 | Minimum voting period (24 h, `MIN_VOTE_HOURS`); nobody can end a vote before everyone has voted; nobody can open or count their own recall; a role removed by a vote returns only by a vote. |
| R-05 | High | **Fake officers and voters.** `POST /members` took `status` and `roles` from the request, so one officer could create voting members and officers in one call. Ran. | ws WS-06 | New people are unit employees with no roles; only members who have joined can hold a role; nobody grants themselves one. **Narrowed, not closed** (second pass, below): the one-call path is gone, but one officer can still bring in people they control. |
| R-06 | High | **Grievance takeover.** A chief steward granted a role yesterday could reassign, decide and close a case they hold no key for, and overwrite another person's sealed key with junk. Ran. | ws WS-07 | Working a case takes its key; assigning never replaces anyone's key. |
| R-07 | High | **Cast order left on disk.** SQLite stores each new row below the previous one in its page, so ballots and receipts sat in the order people voted; with session times, a database copy lined ballots up with voters. Ran (12 of 12 recovered). | ws WS-03, crypto C5 | Every cast rewrites the vote's rows in random order; a test reads the SQLite file back the way a copy would and checks the order. |
| R-08 | High | **The export leaked open votes.** Ballots and receipts of votes still open were included, so polling it isolated each ballot with its receipt. Ran. | ws WS-04 (part) | Ballots and receipts leave only once the vote is counted. |
| R-09 | Medium | **Exports left no trace** in members' access logs. | ws WS-09 | An export writes an entry for each member exported. |
| R-10 | Medium | **A rewritten audit log passed the browser check.** Ran. | crypto C6 | Each device pins the audit log's head, as it already did for the ledger. |
| R-11 | Low | **The 8-character fingerprint** (about 40 bits) could be ground to match a forged history. | crypto C7 | 80 bits, in groups of four hex digits. |
| R-12 | Low | **`INSERT OR REPLACE` skipped the ledger and audit immutability triggers.** Ran. | ws WS-12 (part) | `recursive_triggers` is on. |
| R-13 | Medium | **The confirmation email was a mailer.** Anyone could start a campaign, sign a card and have the server send templated mail to any address. Ran. | campaign C4 | At most three per address per day (in memory only) and a per-campaign daily cap. Host with an email provider quota as well. |
| R-14 | Low | `X-Forwarded-For` was read from its first entry, which the client controls. | campaign C6 | Counted from the end, by number of trusted proxies (`TRUST_PROXY=N`). |
| R-15 | Low | A malformed reshare request returned a 500. | campaign C5 | A 400. |
| R-16 | Info | Shamir `combine()` returned the sender's bytes for an *x = 0* "share". Ran. | crypto C12 | Malformed, repeated and *x = 0* shares are refused before combining. |
| R-17 | Medium | Link secrets (enroll, join, disavow) stayed in the address bar and browser history. | web W3 | Removed once the page has read them. |
| R-18 | Low | A union name such as `[click](https://…)` rendered as a real link in "Our rules". | web W5 | Markdown characters are removed from names. |
| R-19 | Low | Small correctness bugs: `category: "constructor"` accepted; a founding roster listing a role twice returned 500; saving the profile erased location and language; `02-31` accepted as a fiscal year start; the contract-article field (stored in the clear) accepted a narrative. | ws WS-14, WS-08 (part) | Each fixed and tested. |
| R-20 | Medium | **The member's sign-in stays in the browser** and quick exit does not remove it. | web W2 | By design (so members can come back), so quick exit is unchanged: making it wipe the only copy of a worker's access to their private record would be a worse failure. Added **Forget this device**, and said so in the safety tips and the threat model. |
| R-21 | n/a | **Claims stronger than the software.** The public pages said things the review showed were too strong: that the server "can't read" cards (it can if it lies about keys), that the lock applies to a founder, that a recount proves the ballots are the ones cast, that ballots are unlinkable, that `/verify` proves the code you run, and that the lock waits for cards to be "confirmed" (it counts vouched cards). | several | The threat model was rewritten, the README, site, safety tips and the app's own wording were corrected, and the `/verify` page now says what it cannot do. |

### Update, 29 September: key substitution closed for cards and reports

The review's most important open finding ([#36](https://github.com/ChrisRyanWill/project-ludlow/issues/36)) was fixed for the organizing side, with the maintainer's approval, in a change stacked on this one. Every invitation link now carries a 128-bit check of the founder's public keys (in the part of the link the server never sees). Once every trustee has joined, the founder checks each trustee's key words in person and signs the committee's roster; the server stores it but cannot forge it. A signer's or member's browser seals only to the founder (checked against its link) or to the signed roster, refuses anything else before asking the person for anything, and a server that withholds the roster can only cause cards to be sealed to the founder alone. The founder's own re-lock of early cards uses the signed seats, and each trustee checks that their own key is in them. The protocol is in [`docs/PROTOCOL.md`](../PROTOCOL.md) section 1a.

It is tested three ways: adversarial unit tests that play every move a lying server has (swapped, forged, replayed, withheld and lowered-threshold rosters); a tripwire that fails if any code seals to the server's list or builds an invitation without the check; and real-browser tests that alter the server's rows and watch the unmodified app refuse, in the founder-only phase, after confirmation, for reports, and in Spanish. To check the tests are not vacuous, the browser suite was also run with the check switched off, and it failed.

What is still open, and stated in the threat model: the founder is the anchor of trust; a signer trusts whoever gave them the link; the workspace's grievance and vote keys ([#37](https://github.com/ChrisRyanWill/project-ludlow/issues/37)); and everything assumes the app itself was not altered.

### Update, 30 September: a second pass over the fixes

The fixes above had only their author's tests, so three new read-only reviewers (same model family; still not an independent audit) went over the changed code: the roster, the workspace governance fixes, and every public claim against the code. Each claim was re-checked by hand; each fix below was written test first and the new test was seen to fail on the old code. The roster held up: no reviewer could make a genuine client seal to a key the server controls.

| Finding | What changed |
|---|---|
| **Rate limits could be sidestepped behind a proxy.** A hosting company's client-address header was trusted behind any proxy, where it is whatever the client sends. | Only `X-Forwarded-For`, counted from the end, is read; a malformed `TRUST_PROXY` stops the server. |
| **A recall could be blocked or dodged by its target.** Counting required the committee role at count time; stepping down just before the count left no record that a vote removed the role. | Counting is authorized by the vote's own committee; a passed recall marks the role either way. |
| **"No" could pass** for ratification and strike votes (free options and plurality). | Fixed Yes/No with majority or two-thirds. |
| **The confirmation-email caps** could be sidestepped by withdrawing cards and by spelling an address differently; a refused request used up a slot; two simultaneous requests could both send. | In-memory per-campaign count, per-mailbox count, slot reserved only when sending, one send per card at a time. |
| **The founder signed whatever threshold the server listed**, and a trustee link could be placed in the founder's seat. | The founder's device remembers the plan and refuses a different one; the confirm step states the k-of-n; enrollment checks the seat against the link. |
| **A grievance was stranded** when the chief steward changed (a regression from R-06). | Whoever holds the case key can hand it to a new steward or chief steward (adds only, logged for the worker). |
| The WAL journal would put a "has voted" update next to its ballot; the trigger comment overstated what it guards; the tripwire test missed six ways to seal to the server's keys. | Journal pinned to `DELETE`; comment corrected; the tripwire checks each sealing call and tests itself against nine known-bad changes. |
| Many public sentences were stale or too strong (listed in the pull request). | Corrected in the threat model, README, site, the members' data page and the app's own wording. |

**Still open from this pass:** one officer can still bring in accounts they control and give them roles, which weakens two-officer approval and a committee-signed count (#43, now rated High); founding a workspace needs no proof that it comes from a campaign's trustees; whether ratification and strike votes should also require the key to be published. These need design decisions and are described in the pull request for the maintainer.

### Open: needs a design decision or independent review

Each has an issue with the reasoning and options.

| Severity | Finding | Issue |
|---|---|---|
| **High** | **Key substitution, workspace side.** For cards and reports this is now closed (see the update above). Grievances (the chief steward's and stewards' keys) and votes (the election committee's keys and each vote's key) still use keys the server supplies, so a lying server could read new grievances and votes, with the genuine code. | [#37](https://github.com/ChrisRyanWill/project-ludlow/issues/37) |
| High | The ballot key is generated whole in one browser (the committee's and each vote's keys are covered by the row above). | [#37](https://github.com/ChrisRyanWill/project-ludlow/issues/37) |
| High | The release count can be raised by anyone who can mint invites (a plant, or a founder). Ran by one reviewer; another noted it from the code. | [#38](https://github.com/ChrisRyanWill/project-ludlow/issues/38) |
| Medium | Receipts are not tied to ballots, so ballots can be replaced without any check noticing; an operator with modified code can record which session sent which ballot; voters can prove how they voted once the key is published. | [#39](https://github.com/ChrisRyanWill/project-ludlow/issues/39) |
| Low to medium | Request signatures do not cover the body; encrypted fields are not bound to their row; weak passphrases are accepted. | [#40](https://github.com/ChrisRyanWill/project-ludlow/issues/40) |
| Low to medium | Ledger payee commitments are unverifiable; the audit view is a window of 500 unanchored entries. | [#41](https://github.com/ChrisRyanWill/project-ludlow/issues/41) |
| Medium | Grievance clocks start when someone clicks, not from the incident date, so due dates can be later than the contract's. **Treat every date as a reminder.** | [#42](https://github.com/ChrisRyanWill/project-ludlow/issues/42) |
| **High** | Governance: sensitive roles take one officer, and one officer can bring in accounts they control (see the second pass); claim-link transparency; petition deadlines; officer elections (flag off). | [#43](https://github.com/ChrisRyanWill/project-ludlow/issues/43) |
| Low to medium | What a database copy or an officer can still see: audit entries naming workers, session times, small-group subtraction. | [#44](https://github.com/ChrisRyanWill/project-ludlow/issues/44) |
| Low | The Docker image and CI run on Node 20 (end of life); unpinned Actions. Needs the maintainer's decision. | [#45](https://github.com/ChrisRyanWill/project-ludlow/issues/45) |

## What the reviewers checked and found sound

*One line per area, so coverage is visible.*

- **Cryptography.** XChaCha20-Poly1305 with a fresh random 24-byte nonce every time (no reuse); generic errors, so no decryption oracle; sealed boxes bind the recipient key; Shamir splitting (threshold at least 2, random x values, duplicate x rejected, *k*−1 shares fail, resharing checks itself); key files (Argon2id, NFKC, header and format authenticated, KDF parameters tamper-checked, upper limits); member key derivation with separated contexts; challenges are 24 random bytes, single use, 2-minute expiry, and bind route and scope; tokens stored as SHA-256 with constant-time comparison; randomness is libsodium's or `node:crypto`'s, never `Math.random`; ballots have a fixed length and a range check.
- **Campaign server.** Every route's authentication and scoping to the path's campaign (no cross-campaign access found); enrollment tokens are single use; vouch codes are salted with the card id and locked after 5 tries; disavow gives the same answer for a bad card and a bad token; the solo/shared sealing rules; release-number lowering needs *k* distinct approvals of the same value; `export-bundle` is the only route returning card ciphertext; no personal plaintext is persisted; the logging allowlist holds on every path including the 500 path; static files cannot escape the web directory; security headers everywhere; all SQL parameterized; body-size and JSON guards.
- **Workspace server.** The `W()` wrapper authenticates before it checks permissions; every id lookup is scoped to the caller's workspace (no cross-workspace access); claim tokens and challenges are single use; no double voting (one transaction with a guard, races tested); no self-approval or double approval of payments and amounts are bounded; on a single instance the hash chains cannot fork; grievance content, notes and reasons arrive only as ciphertext and the server never gets a case key; encryption at rest fails closed.
- **Browser client.** No `innerHTML`, `eval` or inline handlers; the Markdown renderer allows only `https:` and same-site links; tokens and signatures travel only in headers; the exported package is built entirely in the browser; ballot recount and ledger chain checks run client-side; the CSP is strict and nothing loads from another origin; no open redirects; download file names are sanitized.
- **Supply chain.** `npm audit` reports nothing for runtime dependencies; workflows have read-only permissions, no secrets and no `pull_request_target`.

## What nobody could assess

Behavior in real screen readers and on real low-end phones; Argon2 memory limits on old devices; WAL mode and multi-instance deployments; other SQLite builds and page sizes (the on-disk order test assumes the default); network-level side channels; the legal deadline conventions; whether libsodium's WebAssembly build is constant-time; anything about a real deployment.

## Known blind spots of this review

- One model family wrote and reviewed the code.
- Reviewers each saw one slice, so cross-slice interactions got less attention than they deserve.
- The reviewers were told about the threat model's documented limits and asked not to re-report them, so a documented limit that is *understated* was reported only when a reviewer thought of it.
- No fuzzing, no property-based testing, no formal analysis of the protocols.

## How to check this yourself

```bash
git clone https://github.com/ChrisRyanWill/project-ludlow.git && cd project-ludlow
npm ci && npm test          # unit, API, and real-browser tests
```

Start with `test/workspace.test.js` (the voting, roles and case tests are named for the attacks), `test/campaign.test.js` (seats, release lock, confirmation mail), `test/unit.test.js` (key words, signatures, share checks, pinned history) and `test/sqlite-pages.js` (reads rows out of the database file to check what a copy of it would show).

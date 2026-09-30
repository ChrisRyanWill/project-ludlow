# HANDOFF: Project Ludlow, local session to cloud session

*Written 2026-09-30 by the local Claude Code session that built, published and reviewed this project. Everything you need to continue is in this file. Read it first, then `CLAUDE.md`, `docs/THREAT_MODEL.md`, `docs/PROTOCOL.md` and `docs/reviews/2026-09-internal-review-1.md`.*

**Your job, in order:** (1) **review the completed work** with fresh eyes (section 3); (2) **finish everything incomplete** (section 4); (3) **continue down the prioritized to-do list** (section 5). Section 7 is the context you would otherwise learn the hard way.

---

## 0. The 60-second version

- **What it is:** an open-source (AGPL-3.0-only) platform for workers to form a union privately (zero-knowledge encrypted authorization cards) and then run it democratically (secret ballots anyone can recount, end-to-end-encrypted grievances, a hash-chained ledger). Node + SQLite + vanilla JS, no frameworks. Public at `ChrisRyanWill/project-ludlow`; static project page at https://chrisryanwill.github.io/project-ludlow/.
- **Status:** an *early prototype*, not audited, and it says so everywhere. It was written with AI assistance; the maintainer wants that stated openly and wants every public claim to match what the tests show.
- **Nothing is uncommitted.** All work is committed and pushed. This branch (`handoff/cloud-2026-09-30`) is `main` plus **three open pull requests merged together** (#35, #46, #47) plus this file. All three PRs have green CI, and the integrated tip passes every suite (unit 31, API 76, project site 2, real-browser 15).
- **The owner has not merged any of the three PRs.** Only the owner merges (section 2). Do not try to get around that.
- **The most important open problem** is [#37](https://github.com/ChrisRyanWill/project-ludlow/issues/37): the workspace's grievance and vote keys still come from the server, so a lying server could read new grievances and votes. The same problem for cards and reports was fixed in PR #47.
- **The hard rules** (details in section 7 and `CLAUDE.md`): tests first and prove they fail on the old code; run test suites one at a time, never concurrently; never push to `main`; never claim more than the tests show; no third-party requests, no `innerHTML`; every legal text is a draft.

---

## 1. Project summary and current goal

### What it does

Two halves, one product:

1. **Organize.** A founder creates a campaign in the browser. Coworkers sign electronic authorization cards on their phones. Each card is encrypted *in the browser* with a random key; that key is split k-of-n among trustees (Shamir) and each share is sealed to a trustee's public key. The server holds only ciphertext. One person can start alone: cards are sealed to the founder alone until the founder confirms the committee (see "roster", section 3.3), then re-locked k-of-n. The server enforces a **release number**: it will not hand over the sealed cards until that many are signed and vouched for. In-person vouching, a private encrypted "retaliation shield" record with filing-deadline clocks, and a filing package (roster, cards, declaration, letters, worksheets) built entirely in the browser. Nothing is ever filed or sent for the user.
2. **Run.** Once the union is public, a workspace: accounts claimed with key files, a permission matrix, secret-ballot votes (committee counts in a browser; any member can recount), votes that carry out their own decisions (dues, bylaws, recalls, officer elections behind a flag), petitions and recalls, end-to-end-encrypted grievances with computed deadlines, a hash-chained ledger and audit log, two-officer approval for big spending, small-group suppression, a compliance calendar, a full audited export.

Jurisdiction packs (US NLRA, UK CAC, generic) are data (`web/src/packs.js` + `content/legal/<id>/`). Interface in English and Spanish (Spanish coverage is partial, see 4.7). Strict CSP, no trackers, reproducible builds.

### Current goal

The owner's original brief: *"make a platform anyone could use to make a union and run it better than anyone could imagine ... something that could lead a revolution in workers rights everywhere."* The concrete goals now:

1. **Be trustworthy before being big.** Close the design gaps the security review found, and keep every public claim (README, site, threat model, in-app text) true to the code.
2. **Land the three open PRs** (owner-gated) and verify the deploy.
3. **Build out the roadmap** (issues #12-#32) in order of value.
4. **Prepare for independent human review** (#7, #8, #9, #10, #11). An AI cannot do those; make them easy for humans.

### Stack and shape

| Area | Files |
|---|---|
| Crypto (browser + Node, one file) | `shared/crypto.js` (libsodium + `shamir-secret-sharing` only), `shared/roster.js` (what a browser may seal to) |
| Shared rules as data | `shared/permissions.js`, `shared/constants.js`, `shared/deadlines.js`, `shared/verify.js`, `shared/words.js` |
| Server (plain Node `http`, SQLite via `better-sqlite3`) | `server/campaign.js` (organizing), `server/workspace.js` (the union), `server/db.js` (schema, migrations, triggers), `server/http.js`, `server/auth.js`, `server/kms.js`, `server/mail.js`, `server/rate.js`, `server/log.js`, `server/config.js`, `server/index.js` |
| Front end (vanilla JS, esbuild bundle) | `web/src/*.js` (`ui.js` DOM helpers, `organize.js`, `trustee.js`, `workspace.js` + `ws-*.js`, `exportpkg.js`, `packs.js`, `i18n.js` + `es.js`) |
| Tests | `test/unit.test.js`, `test/campaign.test.js`, `test/workspace.test.js` (API, in-process), `test/e2e.test.js` (real Chromium), `test/site.test.js`, `test/helpers.js`, `test/sqlite-pages.js` |
| Project page | `site/` (built by `scripts/build-site.js`, deployed by `.github/workflows/pages.yml`) |
| Docs | `README.md`, `CLAUDE.md`, `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md`, `docs/reviews/`, `docs/spec/` (the original build prompts; V2 doubles as the roadmap) |

About 5,000 lines of JavaScript in `server/`, `shared/` and `web/src/`.

---

## 2. Repository state at handoff

| Item | State |
|---|---|
| `main` (`d621c50`) | The initial public release: the MVP. The live page is built from it. **No merges since.** |
| PR **#35** `chore/actions-bumps` -> `main` | 1 commit. Five GitHub Actions version bumps combined (checkout 4->7, setup-node 4->7, configure-pages 5->6, upload-pages-artifact 3->5, deploy-pages 4->5). CI green. |
| PR **#46** `security/internal-review-1` -> `main` | 7 commits. The internal security review, pass 1: fixes, a truthful threat model, a review log, corrected site copy. CI green. |
| PR **#47** `security/roster-manifest` -> `security/internal-review-1` | 2 commits, **stacked on #46**. Authenticates the trustees' keys (founder key check in every link plus a founder-signed roster). Closes #36 when it reaches `main`. CI green. |
| Dependabot PRs **#1-#5** | Superseded by #35. They should close by themselves after #35 merges. |
| Issues | #7-#32 are the seed roadmap (review asks, good first issues, features, research); #33 is the pinned roadmap; #34 is the welcome Discussion; **#36-#45 are the design-level findings from the review**. |
| **This branch** | `handoff/cloud-2026-09-30` = `security/roster-manifest` + a merge of `chore/actions-bumps` + this file (+ `handoff/tools/`). It contains all open work. It merged with no conflicts. |

**How to relate your work to the open PRs.** Work on this branch or branches off it. Open your pull requests **against `main` only after #35/#46/#47 have been merged** (so the diff is clean); until then, either stack them on this branch or on the relevant PR branch. If the owner merges the three PRs (squash or merge commit), `git fetch && git merge origin/main` into your working branch: the content is identical, so expect no conflicts (unless the owner edited something while merging; their version wins). **Pushing a branch does not run CI** (`ci.yml` runs on pushes to `main` and on pull requests), so open a PR to get CI.

**Merging is the owner's call.** The local session tried to merge PR #35 through the CLI once and the harness's permission check refused it ("Merge Without Review"). Do not work around a refusal like that (no direct pushes to `main`, no API tricks). If your own permissions do allow merging, still do not merge without the owner's explicit say-so: they want to review this work. Say in the PR what needs their attention.

**GitHub repository settings already done:** public; Discussions on, wiki off; private vulnerability reporting on; secret scanning and push protection on; Dependabot (npm weekly, Actions monthly); Pages built from Actions; 15 topics; custom labels (`needs-legal-review`, `security-review`, `translation`, `jurisdiction`, `research`); `delete branch on merge` on. **Not done (owner):** branch protection on `main`, a social-preview image, the Node minimum decision (#45).

**The live site.** https://chrisryanwill.github.io/project-ludlow/ returns 200 and is the `main` build from 2026-09-28. It shows none of the review-era copy fixes until #46 merges (the Pages workflow runs only on pushes to `main` that touch `site/**`, `shared/**`, `scripts/build-site.js` or the workflow file).

---

## 3. Completed, and how to verify it

### 3.0 Verify everything in five minutes

```bash
npm ci
npx playwright-core install --with-deps chromium   # or set CHROME_PATH to any Chromium
npm run test:unit   # expect 31 pass
npm run test:api    # expect 76 pass (32 campaign + 44 workspace)
npm run test:site   # expect 2 pass
npm run test:e2e    # expect 15 pass
```

**Run them one after another, never at the same time** (section 7, "Tests"). The integrated code (`8eca6df`, the last commit before this file and the tools folder were added, which changed no code) was measured this way on 2026-09-30: unit 31, API 76, site 2, e2e 15, zero failures. CI on each of the three PRs is also green (unit+API on Node 20 and 22; browser end-to-end).

The 15 browser tests are the product journey, in order: home page under the strict CSP and quick exit; one person creates a campaign with a release lock and it is live at once; a trustee invites coworkers and people sign cards; pending cards confirmed in person and a member invites a coworker; a signer keeps a private record and shares one entry; **a lying website cannot make a phone seal to its own keys (founder-only phase)**; the other trustees join and the founder confirms the committee; **the same after confirmation**; k trustees open the cards and build the package; the trustees start the workspace; accounts are claimed; a secret-ballot vote is counted and recounted; the books and ledger chain; a worker files a concern; the whole signing flow in Spanish (including a Spanish refusal message).

### 3.1 On `main`: the MVP (everything a user can do)

- **Organize:** a step-by-step wizard (including the release number and the founder-first committee), trustee enrollment (Argon2id-protected key files), direct and group invitations with QR codes, signing in English or Spanish, cards carrying the fields NLRB GC 15-08 requires and the emailed Confirmation Transmission (the signer's details pass through the server once, are sent, and are not stored), in-person vouching with a 5-try lockout, progress with momentum and legal-threshold markers, the private locker with filing-deadline clocks, sharing one entry with the committee, pause/destroy (destroy needs k trustees), the unlock ceremony, the filing package.
- **Release lock:** server-enforced (`export-bundle` is the only route that returns card ciphertext); raising the number is free, lowering needs k trustees agreeing on the same value.
- **Workspace:** founding from the trustees' browser (they must confirm the union is public), claim links, roles from a data-driven permission matrix (a test walks the route table), votes/petitions/recalls, grievances with a configurable procedure and holidays, ledger and two-approval disbursements, bylaws versions, health with small-group suppression (`SMALL_GROUP = 5`), compliance calendar, full export.
- **Front end:** dark mode, quick exit (button and triple Esc), discreet tab titles, read-aloud, EN/ES, navy/ultramarine/gold identity with serif headlines.
- **Project page** with a real-crypto "Try the lock" demo (`site/src/try.js` reuses `shared/crypto.js`).
- **Contributor infrastructure:** CONTRIBUTING, Code of Conduct, SECURITY.md (private reporting), issue and PR templates, CODEOWNERS, CI, Dependabot, AGPL-3.0 `LICENSE`.
- **Reproducible builds:** `npm run build` prints the SHA-256 of `app.js`; a local build and the Docker build produced byte-identical output when checked on `main` (not re-checked since #46 and #47; see P3.7). The Docker image builds and runs in production mode.

### 3.2 PR #46: internal security review, pass 1

Four read-only adversarial reviewers (crypto, campaign server, workspace server, web client) plus a hand supply-chain check; every claim was re-verified against the code; each fix was written **test first and confirmed to fail on the old code**. The full record, including what was found sound and the blind spots, is `docs/reviews/2026-09-internal-review-1.md`. **It is not an independent audit** (one model family wrote and reviewed the code).

Fixed, each with tests (search the tests by these names): trustee seat takeover (`trustees/reset` was open to any trustee); a single committee member could post a made-up tally that the server then applied (recalls, dues, bylaws); "No" could win as "passed" under plurality; a recall's target could open it with a seconds-long window, close it, or sit on its committee; one officer could mint officers and voters through `POST /members`; a keyless chief steward could take over a grievance; ballot cast order was left in the SQLite file (every cast now rewrites that vote's rows in random order; `test/sqlite-pages.js` reads the file the way a database copy would); exports leaked open ballots and left no trace; `INSERT OR REPLACE` bypassed the immutability triggers; confirmation email abuse (per-address and per-campaign caps); `X-Forwarded-For` spoofing (`TRUST_PROXY` is now a hop count); Shamir shares with x = 0; link secrets left in browser history; markdown injection through the union name; audit-log head pinning per device; 80-bit ledger fingerprints; "Forget this device". Plus honest rewrites of the threat model, README, safety tips and site.

### 3.3 PR #47: authenticate the trustees' keys (the "roster")

Closes #36 for the organizing side. Specification: `docs/PROTOCOL.md`, the paragraph "1a. Authenticating the trustees' keys" inside section 1. In short:

- Every invitation link carries `f`, a 128-bit hash of the founder's public keys, in the URL fragment (never sent to the server).
- When every trustee has joined and the founder has checked each trustee's **key words** (10 words, about 77 bits) aloud, the founder signs `{campaignId, k, n, seats}` and uploads it (`POST /api/campaigns/:id/roster`, founder-only). The server stores it and only then accepts k-of-n cards.
- `shared/roster.js` `authenticate()` decides what a browser may seal to: the founder alone (checked against the link) or the signed seats; anything else is refused before the person is asked for anything. A server that withholds the roster can only make cards founder-only.
- A **unit tripwire** (`frontend trust: ...` in `test/unit.test.js`) fails if any code seals to the server's trustee list or builds an invitation link without `f`. `CLAUDE.md` rule 9c.
- **Negative proof:** with `authenticate` switched to the old behavior, exactly the three browser tests that tamper with server rows (two in English, one in Spanish) failed and the other twelve passed.

Behavior changes to know: cards stay founder-only until the founder **confirms** the committee (not merely until everyone has joined); reports go to the founder alone until then; links without `f` are refused (older dev links); the wizard no longer shows other trustees' links; two nullable columns on `campaigns` (`roster_json`, `roster_sig`, migrated automatically). It also fixed a stale page: "How your data is protected" (`content/legal/common/data-protection.md`) still said trustees could open cards before the release number, which was false.

### 3.4 PR #35: Actions version bumps

Nine lines across `ci.yml` and `pages.yml`. CI green on the PR. **Unverified on `main`:** `pages.yml` runs only on pushes to `main`, so the bumped `configure-pages@v6`, `upload-pages-artifact@v5` and `deploy-pages@v5` have never run for real. See 4.2.

### 3.5 What to scrutinize when you "review the completed work"

**The fixes in #46 and #47 have only their author's tests.** The adversarial review examined the *original* code, not the fixes. A second, independent adversarial pass over the new and changed code is the single best use of your first hours. Look hardest at:

1. `shared/roster.js`, the roster route in `server/campaign.js`, and how `JoinPage`, `MemberPage` and `trustee.js` use them. Try to make a genuine client seal to a key the founder did not vouch for. (Known soft spots: the `committee_changed` retry path in `JoinPage` has no browser test; legacy members without a stored founder check, P3.6.)
2. The tally attestation flow: `signTally`/`verifyTally` in `shared/crypto.js`, the `results` route in `server/workspace.js`, and `TallyPage` in `web/src/ws-votes.js` (each contributing member's signing key is held in memory during the ceremony).
3. The governance rules (roles route, `POST /members`, grievance access via `grievanceFor`, recall rules) for gaps and for legitimate flows they now block.
4. `scrambleVote` (per-cast rewrite; cost is O(n) per cast) and `PRAGMA recursive_triggers = ON` (it also makes `ON DELETE CASCADE` fire the immutability triggers, which matters for #27).
5. `docs/THREAT_MODEL.md` against the code: every sentence should be true. Check the new text as skeptically as the old.

---

## 4. Incomplete work: state and what is left

| # | Item | State now | What is left |
|---|---|---|---|
| 4.1 | PRs #35, #46, #47 | Open, CI green, unreviewed by the owner | **Owner review and merge** (#46 before #47). Not yours to do. |
| 4.2 | Post-merge verification | Not started (needs the merges) | After #35 merges: watch the `Project site` run on `main` (it starts because #35 edits `pages.yml`). If the deploy fails with the new action versions, revert only the `pages.yml` bumps and keep `ci.yml`; the live page stays on the last good deployment. After #46 merges: confirm the page shows the corrected copy. Then: close #36, tick the roadmap #33, update `docs/reviews/2026-09-internal-review-1.md`, delete merged branches. `handoff/tools/live-check.mjs` smoke-tests the deployed page in a real browser (read its header first). |
| 4.3 | **#37 workspace keys** | **Not started.** Needs a design decision | Section 5, P1.1. |
| 4.4 | Issues #38-#45 | Not started; each has a written description | Section 5. |
| 4.5 | Roadmap features #12-#32 | Not started | Section 5, P2. |
| 4.6 | Stale screenshot | `site/img/committee.png` (used in `site/index.html`) shows the trustee dashboard from before #46 (no key words, no "Confirm the committee"). The other five site screenshots are still roughly right. | Regenerate: `SHOTS=/some/empty/dir npm run test:e2e` writes a PNG for every `shot()` call in `test/e2e.test.js` (`SCHEME=dark` for dark mode); the new committee screens are `06b-committee` and `06c-key-words`. `card.png` and `progress.png` are byte-identical to the e2e shots `04-sign-card` and `05-member-progress`; the others were made the same way (by name: `01-home`, `06-trustee-dashboard`, `10-money`, `09-vote-results`, the last two in dark mode) but could not be matched byte for byte, so compare by eye. Then replace `site/img/committee.png`. |
| 4.7 | Spanish coverage | The signing flow, the home page and some pages are translated (111 strings in `web/src/es.js`, none orphaned). Strings with **no Spanish entry**, by file: `web/src/trustee.js` 129 of 131, `ws-votes.js` 95 of 95, `workspace.js` 108 of 112, `organize.js` 166 of 241, `pages.js` 14 of 36. The site says "English and Spanish today" and the README lists "English and Spanish" (and says the translation is a first draft), but neither says that the trustee dashboard, votes and most of the workspace are still English-only. | Either translate the rest (a native reader should review, #10) or state the coverage precisely on the site and README. |
| 4.8 | Test-quality debts from the review | Not started | Section 5, P3 items 1-4. |
| 4.9 | Independent human review | Not started; cannot be done by an AI | #7 (cryptography), #8/#9 (attorneys), #10 (Spanish), #11 (accessibility). Help the owner prepare a reviewer packet. |
| 4.10 | Owner decisions still pending | Waiting on the owner | Section 5, P0 item 4. |

There is **no half-written code** anywhere: nothing was left mid-edit, and no work was discarded.

---

## 5. Prioritized to-do list

Definition of done for anything below: a test that fails without the change (prove it by reverting only the fix), the docs synced (section 7, "Docs drift"), a PR whose description says plainly what changed and what did not, and `docs/THREAT_MODEL.md` / the review log updated if a security property changed.

### P0: verify, then unblock

1. **Review the completed work** (section 3.5). Write findings as failing tests and PR comments; fix what you can.
2. Run every suite once, sequentially, and record the numbers.
3. **Owner-gated:** ask the owner (in a PR comment) to review and merge #46, then #47, then #35. Do not merge them yourself. When they have, do 4.2.
4. **Owner decisions** (ask in a PR comment; propose your recommendation and proceed on a branch):
   - **Node (#45).** Node 20 is end-of-life and is in the Dockerfile and CI. Recommendation: build the image and run CI on Node 22 and 24 while keeping `engines` at `>=20` so local development on 20 still works. (Dependabot's `better-sqlite3` 13 needs Node >= 22 and crashes on 20; PR #6 was closed for that and Dependabot was told to ignore that major.)
   - **#37 anchor of trust** (below).
   - Strip the `Claude-Session:` URL trailer from the public history? (History rewrite; only sensible while nobody has cloned.) Default: leave it.
   - Branch protection on `main`; a social-preview image; whether to ever host a public instance (default: **no**, see section 7).

### P1: security (highest value first)

1. **#37 Workspace keys.** Grievances (chief steward and steward keys via `/api/ws/keyring`), the election committee's keys, and each vote's public key all come from the server. #47 solved the organizing side with the *founder* as anchor of trust; the workspace has no equivalent anchor, so the design is the hard part. Options are in the issue (founding officers sign a workspace roster with a key check carried in each claim link; role grants signed by officers and verified by members' browsers; reuse the #47 pattern with the founding trustees as signers). Suggested path: (a) write a short design note with a threat analysis and open a PR for the owner to react to; (b) ship the cheap, real improvement first (per-device pinning of role holders' box keys with a loud change alert, and key words shown for chief stewards and the committee); (c) then the signed roster. Also decide who generates a vote's key (today it is generated by `newVoteKeys` in the browser of whoever opens the vote, which holds all of it before splitting; generating it with the committee is the fix, and at minimum require the opener to be a committee member and show key fingerprints). The test model to copy: `authenticate` tests in `test/unit.test.js` plus browser tests that alter DB rows.
2. **#38 Release count integrity.** Direct invites count immediately and can be made by any trustee or vouched member, so an insider can inflate the count. Options: cap direct invites per non-trustee member, require a second, different member's vouch, show trustees the provenance of the count, let trustees flag or discount cards when they open them. No option is a proof; the goal is that inflating it takes more than one insider, and that the docs say exactly what the lock guarantees.
3. **#43 Governance remainder.** Second approval (or a vote) for granting `officer`, `treasurer`, `chief_steward`, `election_committee`; claim-link transparency; petitions that auto-open and the unenforced 14-day deadline; workers reopening closed cases; **fix the officer-election logic before `ONLINE_OFFICER_ELECTIONS` is ever offered** (labels and member ids are independent and never shown).
4. **#40 Crypto hardening.** Sign the request body (`signAuth` covers only `nonce|route|scope`); bind encrypted fields to their row (`server/kms.js` AAD is only the column name; migration must read both formats) and bind a card to its id; verify `cardTextSha256` against the card text when opening cards (`web/src/exportpkg.js`); passphrase strength (`passphraseOk` is only a length rule, and the encrypted key files live in `localStorage` as `tk.*` and `mk.*`, so the passphrase and the Argon2id cost are the only protection if a device is copied).
5. **#41 Ledger and audit.** Members never get the ledger `commit` salt, so payee/memo commitments cannot be checked, and payee, memo and `created_by` are outside the hash; the audit view is the newest 500 entries, unanchored, and a roster view writes one entry per member.
6. **#44 What a database copy or an officer can still see.** Audit entries name the worker who filed; session timestamps; subtraction defeating small-group suppression.
7. **#42 Grievance deadlines.** Clocks start when the case is filed and when a steward clicks; there is no incident or answer date, so due dates can be later than the contract's. Add an explicit start date per step (with an audit entry) and label which date each deadline counts from. Needs a steward or attorney to confirm which events matter: flag it `needs-legal-review`.
8. **#39 Ballots (research write-up).** Receipts are not tied to ballots (deliberately, for receipt-freeness), so replaced ballots go unnoticed; an operator with modified code can log which session sent which ballot; voters can prove how they voted once the key is published. Produce a recommendation on what to promise and what to stop promising.
9. **Not yet filed as issues (file them, then fix):**
   - `POST /api/ws` (founding) needs no authentication and is not tied to a campaign (its only check is a `confirmedPublic: true` field that any caller can send). It accepts up to 10 MB and 3,000 members per request at the strict per-IP limit (90 per minute by default). So anyone can create workspaces with any union name and fill the database: a storage-abuse and impersonation vector. Options: a proof from the campaign's trustees (for example a signature by the founder over the workspace's first officers), smaller caps, or a confirmation step. Design it together with #37.
   - **Master key footgun:** without `NODE_ENV=production` the server writes `data/dev-master.key` next to the database. Consider refusing to bind a non-loopback `HOST` without `WORKSPACE_MASTER_KEY`.
10. **#7 Independent review** stays open; help prepare the packet (scope, protocol diagrams #14, how to run, the review log, the tests).

### P2: product and roadmap (choose by value)

Best value per effort first: **#12** add a language (one file); **#13** deployment guide (docs); **#14** sequence diagrams for `docs/PROTOCOL.md` (Mermaid; helps every reviewer, include the new roster flow); **#45** runtime and Actions pinning; **#16** JSDoc types with `tsc --checkJs`; **#15** the site in Spanish. Then the big lever for adoption: **#18** an in-browser demo of the *whole* app (port the storage layer to WebAssembly SQLite behind the same interface, serve under `/project-ludlow/`, persona switcher, seeded fake data; must run the real `web/` code, not a fork). Then features as capacity allows: #21 surveys with small-group suppression (reuse `SMALL_GROUP`), #22 meetings and minutes, #24 hardship fund (privacy-critical: seal requests like grievances), #26 passkeys (security-sensitive; needs a design first), #27 workspace deletion (tension with the immutable ledger and with `recursive_triggers`), #19 dues checkout and LM-2/3/4 (needs a design that keeps card data off our pages), #20 officer elections (needs attorney sign-off), #23 contract library, #25 joint committees, #28 official PDF forms, #29 offline mode, #17 new jurisdiction packs, #30/#31/#32 research.

### P3: quality and tech debt

1. **Conditional test.** In `test/unit.test.js`, the wrong-key case in "secret ballots: sealed to a key nobody holds whole" is `if (wrong) assert...`, so it passes without testing anything when the promise rejects. Make it unconditional.
2. Other test gaps the crypto reviewer listed: key-file KDF/nonce/format tampering; `openReport` with a different id; `countBallots` with out-of-range options and duplicates; `canonicalJson` edge cases.
3. **An e2e test for the `committee_changed` retry** in `JoinPage`: load the signing page, then flip the roster on the server, then submit.
4. **e2e resilience.** It is one file with shared state, so an early failure cascades, and it is load-sensitive (section 7). Consider more resilient waits or smaller independent journeys.
5. **`articleRef` validation is strict.** `^[A-Za-z0-9 .§-]{1,20}$` (server and `ws-help.js`) rejects real references such as `Art. 5(b)` or `12/3`. Widen it carefully; it exists so a narrative is never stored in the clear.
6. **Legacy member records.** A device that signed before #47 has no stored founder check, so it cannot share a report or make an invitation until it opens a fresh member link; the message shown (`no_commit`) reads oddly for a member. Only affects pre-existing dev data.
7. `pdf-lib` has had no release since 2021; pin Actions by commit SHA; add Dependabot's `docker` ecosystem; add a Docker `HEALTHCHECK`; add a CI check that the local and Docker `app.js` hashes match.
8. Spanish coverage (4.7); accessibility testing with real assistive technology (#11) and forced-colors support; measure Argon2id unlock time on low-end phones (#31).
9. `docs/spec/` is the original build prompt and is partly out of date relative to what was built; do not treat it as current.
10. **Legal drafts are not yours to finish.** Every text in `content/legal/` is a draft that needs a licensed attorney; at handoff `grep -r 'TODO(lawyer)'` finds 38 markers (22 of them in `content/`) and `TODO(accountant)` finds 6. Never remove a marker or the `DRAFT` header to make something look finished, and never invent a legal requirement (rule 13).

---

## 6. Install, run, and test

**Requirements:** Node >= 20 (CI tests 20 and 22), npm, and a Chromium for the browser tests (Playwright-core does not bundle one). Docker is optional.

```bash
npm ci                                             # install (runtime: better-sqlite3, libsodium-wrappers-sumo,
                                                   #   shamir-secret-sharing, pdf-lib, qrcode-generator; dev: esbuild, playwright-core)
npx playwright-core install --with-deps chromium   # for the browser tests; or export CHROME_PATH=/path/to/chrome
npm start                                          # build web/dist, then serve http://localhost:8787
npm run dev                                        # same, restarting on server changes
npm run build                                      # just the web bundle; prints SHA-256(app.js)
npm run build:site                                 # the project page into site-dist/
```

Data lives in `data/` (SQLite file and, outside production, `dev-master.key`); it is git-ignored. Docker (the image already sets `NODE_ENV=production`, `DATABASE_PATH=/data/ludlow.db`, `PORT=8787` and `HOST=0.0.0.0`; the header of the `Dockerfile` has the full example):

```bash
docker build -t project-ludlow .
docker run -p 8787:8787 -v ludlow-data:/data -e APP_BASE_URL=https://your.domain \
  -e WORKSPACE_MASTER_KEY="$(openssl rand -base64 32)" -e TRUST_PROXY=1 project-ludlow
```

Keep the generated master key: without it the workspace's encrypted fields cannot be read. (For anything but a throwaway container, generate it once, store it in a secret manager, and pass it in.)

| Command | What it runs | Expect |
|---|---|---|
| `npm run test:unit` | crypto, rosters, deadlines, permissions, hygiene tests | 31 pass, seconds |
| `npm run test:api` | the API in process against a temp database (`campaign` + `workspace`) | 76 pass (32 + 44), about a minute |
| `npm run test:site` | builds the project page and drives it in Chromium (incl. the demo) | 2 pass |
| `npm run test:e2e` | the whole product in real Chromium with the real CSP | 15 pass, about 2 minutes on CI, longer on a loaded machine |
| `npm test` | build, then everything under `test/`, one file at a time | all of the above (31 + 76 + 2 + 15 = 124 tests) |

**If no Chromium is found, the site and browser suites are reported as skipped, not failed.** That can look like a green run. Check that the output says `pass 2` and `pass 15`, not `skipped`.

**Environment variables** (names only; none is required for development; read in `server/config.js`):

| Variable | Default | Meaning |
|---|---|---|
| `PORT`, `HOST` | `8787`, `127.0.0.1` | Listen address (`HOST=0.0.0.0` in containers) |
| `DATABASE_PATH` | `data/ludlow.db` | SQLite file |
| `APP_NAME`, `APP_BASE_URL` | `Project Ludlow`, `http://localhost:PORT` | Branding; base URL used in confirmation emails |
| `NODE_ENV` | unset | Set `production` on any real server. Without it the master key is written next to the database |
| `WORKSPACE_MASTER_KEY` | dev key file | **Secret.** 32 bytes, base64. Required in production and whenever `HOST` is not loopback (Cloud Log); back it up separately from the database |
| `EMAIL_PROVIDER` | `dev` | `dev` (in-memory outbox, never persisted) or `postmark` |
| `POSTMARK_SERVER_TOKEN` | | **Secret.** Real email |
| `EMAIL_FROM`, `CONFIRMATION_REPLY_TO` | `noreply@localhost`, empty | Email addresses |
| `CAMPAIGN_INACTIVITY_DAYS` | `180` | Idle campaigns are deleted by a sweep in `server/index.js` |
| `GROUP_INVITE_TTL_HOURS`, `DIRECT_INVITE_TTL_DAYS` | `72`, `7` | Invitation lifetimes |
| `ONLINE_OFFICER_ELECTIONS` | off | Feature flag; only the exact value `true` turns it on. Keep it off until an attorney signs off (and #43 is fixed) |
| `MIN_VOTE_HOURS` | `24` | Shortest a vote may stay open (`0` in tests) |
| `SESSION_IDLE_HOURS`, `SESSION_MAX_DAYS` | `12`, `30` | Workspace sessions |
| `RATE_STRICT_PER_MIN`, `RATE_LIMIT_DISABLED` | `90`, off | Rate limiting; only the exact value `1` disables it (tests only) |
| `TRUST_PROXY` | `0` | Number of reverse proxies in front (1 for Caddy or nginx) |
| `CONFIRMATIONS_PER_CAMPAIGN_PER_DAY` | `2000` | Cap on confirmation emails per campaign |
| test only: `CHROME_PATH`, `SHOTS`, `SCHEME`, `TZ` | | Chromium binary (otherwise found under `~/.cache/ms-playwright`); folder to save e2e screenshots into; `dark` for dark mode; some tests set `TZ` themselves to check that date-only values do not shift days |

**CI.** `.github/workflows/ci.yml` runs on pushes to `main` and on all pull requests: unit + API on Node 20 and 22, and the browser suite (it installs Chromium with `npx playwright-core install --with-deps chromium`). `pages.yml` deploys `site/` on pushes to `main` that touch `site/**`, `shared/**`, `scripts/build-site.js` or the workflow, and on manual dispatch.

---

## 7. Tricky things and context you would not otherwise know

### Working agreements (from the owner and from `CLAUDE.md`)

- **`CLAUDE.md` rules are non-negotiable.** The ones that matter most: no plaintext personal data persisted by the campaign system; never log bodies, queries, headers, tokens or IPs (allowlist in `server/log.js`); secrets live in URL fragments; only libsodium and Shamir, only in `shared/crypto.js`; **no third-party requests, no `innerHTML`, no `eval`, no inline scripts or styles** (tests enforce it); every legal text is a draft with the header `DRAFT — REQUIRES REVIEW BY A LICENSED LABOR ATTORNEY BEFORE REAL-WORLD USE` and `TODO(lawyer)` markers; `export-bundle` is the only route that may return card ciphertext and it must check the release number; cards are sealed solo only while the roster is unsigned; **rule 9c: seal only to keys authenticated by `shared/roster.js`**; every workspace route goes through `W()` and the permission matrix test walks the route table; ballots are unlinkable (`ws_ballots` and `ws_vote_receipts` have no member reference and no timestamp); representation is never gated by dues or membership.
- **Tests first, and prove they fail.** Write the failing test, watch it fail, fix, watch it pass, then revert only the fix and confirm it fails again. Every finding in the review log was handled this way. State in PRs how you proved it.
- **Honesty is a feature.** The threat model, README, site and in-app text must match the tests. Never say "audited", "unhackable", "the server can't ever..." Describe limits in plain words.
- **The owner's communication style:** plain-language summaries first, no jargon walls; give a best guess with a rough confidence and a source when you are unsure, never a bare "unverified"; ask before publishing, merging or spending, and propose a default when you ask.
- **Decisions the owner already made (do not relitigate):** the product name is exactly **"Project Ludlow"**; license **AGPL-3.0-only**; commits are authored as the GitHub handle with the noreply email; the visual identity is navy/ultramarine/gold with serif headlines (**not green**: the owner said green matched another of their projects); a **public** repo with a static project page and **no hosted instance of the real app** (it is an unaudited security tool; a public server would invite real use); the release number must be **enforced**, not advisory; **one person must be able to start alone** (founder-first); Node 20+ is supported today.
- **Public repo etiquette.** Issues describe design gaps at a level the maintainers chose. Do not add working exploit recipes for unfixed problems to public issues or docs. If you find something that could hurt people using a deployed copy, use private vulnerability reporting (`SECURITY.md`).
- **Never:** push to `main`; merge without the owner; add analytics, CDNs, external fonts or images; change the license; claim an audit; commit secrets. Use the commit attribution your own harness requires.

### Tests

- **Run suites one at a time.** The browser suite uses a 90-second default action timeout because key derivation (Argon2id at 256 MB, falling back to 64 MB when a device cannot allocate that) is slow on a busy machine. On a shared machine, running anything else at the same time produced false timeouts that pass when run alone. Also do not `git stash` or switch branches while a suite runs.
- The browser suite is **one file with shared state** (later tests use links and accounts made by earlier ones). It runs the real server in process and **edits database rows directly** to play a lying server (`h.app.db`). The tamper tests depend on that.
- `test/helpers.js`: `startApp()` defaults to `minVoteHours: 0` and `rateLimitDisabled: true`; `makeCampaign()` **auto-confirms the roster** when the committee is complete (`confirm: false` leaves it unsigned; `enroll: 1` gives a founder-first campaign); `signCard()` seals by `camp.confirmed`; `confirmRoster()` is the founder's signing step. In `test/workspace.test.js`, the local helper `endVote(ws, id)` moves `closes_at` into the past because votes can no longer be closed early.
- `test/sqlite-pages.js` parses the SQLite file's b-trees to read rows in physical order. It assumes the default rollback-journal mode and page layout.
- `test/unit.test.js` includes scanners over `web/src` (no `innerHTML`, every UI helper is imported, the roster tripwire). New browser code must satisfy them.

### Architecture gotchas

- `shared/` runs in **both** the browser and Node: no DOM and no Node-only APIs there.
- **Translations are keyed by the English sentence** (`t('...')`, `web/src/es.js`). If you reword an English string, the Spanish entry silently stops matching. When you change an English string, search `es.js` for the old one.
- The CSP forbids inline styles; build DOM with `web/src/ui.js` (`h()` uses `textContent` and the CSSOM). The Markdown renderer `md()` only allows `https:` and same-site links, so any user-supplied text that goes into Markdown must first pass through `plainMd()` in `web/src/format.js` (a unit test covers it).
- Date-only strings (`2026-10-05`) must display as the same calendar day everywhere; use `web/src/format.js`. This was a real bug (a legal deadline shown a day early).
- `server/campaign.js` sealing rules: `POST /api/cards` accepts **solo** cards until a roster exists and **k-of-n** only after; `reshare` needs the roster; reports go to the founder alone until the roster exists, then to every trustee. `committee_changed` (409) makes the signer's browser re-fetch, re-authenticate and re-seal.
- Votes: a decision with an effect must publish the ballot key so the server recounts; a result posted without the key needs k committee members' signatures (`signTally`) over the same counts; votes cannot be closed early (only when everyone has voted) and have a minimum window; nobody runs their own recall; a role removed by a vote returns only by a vote (`ws_roles.removed_by_vote_id`).
- `PRAGMA recursive_triggers = ON` is deliberate (it makes `INSERT OR REPLACE` fire the immutability triggers).
- **Things that look like bugs but are intended:** cards stay `solo` after every trustee has joined until the founder confirms; the wizard does not show the other trustees' links; the roles screen refuses to re-grant a recalled role; a vote cannot be closed early; links without `f` are refused.

### Docs drift (a real trap)

User-facing text drifts. `content/legal/common/data-protection.md` (the page members read at `/protected`) contradicted the release lock for weeks before anyone noticed. When a security property changes, search `README.md`, `site/`, `content/`, `web/src/*.js` and `docs/` for the old claim, not just the file you edited.

### Environment differences

- The local machine's session scratch files (the reviewers' proof-of-concept scripts, issue-seeding scripts) are **not** in this repo and you cannot see them. The fixed findings all have tests; the unfixed ones are described in issues #36-#45. Only `handoff/tools/live-check.mjs` was kept.
- The owner runs a local development server and a database of test data on their own machine. That is not accessible to you and is irrelevant.
- The local session cannot receive replies from you. Use PR descriptions, PR comments and issue comments to communicate with the owner.
- Anything that is not in this file, the repository or the GitHub issues and pull requests did not carry over from the local session.

### Budget

This work runs on a limited budget, so spend it where it counts. Suggested use, best value first: an independent adversarial review of the new code (P0.1); #37 (design note first); #38, #43, #40; the docs items #13 and #14; then #18 (the in-browser demo). Use subagents for breadth (review, translation, test writing) and verify their claims yourself before acting; reviewers' reports contain both real findings and overstatements, and a few of them were narrowed on inspection.

---

## 8. Glossary

**Founder** = trustee 1, who can start alone. **Trustee** = holds a key share; k of n open the cards. **Solo card** = sealed to the founder alone. **Roster** = the committee (`{campaignId, k, n, seats}`) signed by the founder. **Founder key check (`f`)** = 128-bit hash of the founder's public keys carried in every invitation link. **Key words** = 10 words identifying a public key, read aloud to check it. **Release number** = how many vouched cards must exist before the server hands over ciphertext. **Effect vote** = a vote whose decision the server carries out (dues, bylaws, recall, officer election). **Vouched** = a card counted (direct invite, or confirmed in person for group links). **Small-group suppression** = breakdowns under 5 people are hidden.

---

## Cloud Log

*Kept by the cloud session that took over on 2026-09-30. Newest entries last. Work happens on branch `ccr-4bbdd9ba-k1u637` (cut from `handoff/cloud-2026-09-30` at `24beaa5`); its pull request targets `handoff/cloud-2026-09-30` so CI runs and the diff stays clean until the owner merges #35/#46/#47.*

### 2026-09-30

- **Suites on the handoff tip (`24beaa5`), run one at a time:** unit 31/31, API 76/76, site 2/2, browser 15/15 (Chromium from `/opt/pw-browsers`, about 60 s). Matches the handoff.
- **P0.1 started:** three independent read-only reviewers (roster/organizing trust; workspace governance and tally attestation; threat model and docs against the code, plus the small server changes). Their findings are verified by hand before anything is changed; results are logged below.
- **P3.1 and P3.2 done** (`test/unit.test.js`): the conditional wrong-share assertion is unconditional; new negatives for key files (format, nonce, ciphertext, salt, opslimit, algorithm, malformed), reports (replayed under another id, absent seat), ballots (out-of-range choices, sealed to another key, duplicates documented as the server's job) and `canonicalJson`. Proof: six mutations of `shared/crypto.js`, each fails the suite; the old conditional passed the first.
- **P1.9 master key footgun: done.** `loadMasterKey` (`server/kms.js`) now refuses to write `dev-master.key` when `HOST` is not a loopback address (`127.x`, `::1`, `localhost`); the server exits with a message naming `WORKSPACE_MASTER_KEY`. Test `master key: ...` in `test/unit.test.js` failed before the change. README, threat model and the table above updated. *Behavior change to know:* `HOST=0.0.0.0 npm start` without a key now stops at start. The Docker image is unaffected (it already sets `NODE_ENV=production`, which requires the key).
- **P3.5 `articleRef` widened: done.** One pattern, `ARTICLE_REF` in `shared/constants.js`, now used by the server and the grievance form. It adds `,` `/` `(` `)` so `Art. 5(b)`, `12/3` and `Art. 7, 9` are accepted; still at most 20 characters, and `;`, `<`, `@`, `[`, newlines stay refused. The extended test in `test/workspace.test.js` failed on `Art. 5(b)` before the change.
- **P3.7 (part): Docker `HEALTHCHECK` and Dependabot `docker` ecosystem: done.** The health check fetches `/` over loopback with Node's built-in `fetch` (no curl in the slim image); each check logs one allowlisted line. Verified the command against a running and a stopped server (exit 0 / 1). **Not verified:** a real `docker build` (no Docker daemon in this container); the owner or CI should build the image once. Dependabot ignores Node **major** bumps of the base image because the Node version is an owner decision (#45). Still open in P3.7: pin Actions by SHA, a CI check that local and Docker `app.js` hashes match, `pdf-lib` staleness.
- **#14 sequence diagrams: done** (`docs/PROTOCOL.md` section 5: founder-first and the roster, signing with the `committee_changed` retry, opening under the release lock, a secret ballot with both tally paths). Two claims in section 2 corrected while writing them: the vote's whole secret key *does* exist briefly in the opener's browser (it said "exists nowhere"), and the tally-attestation path and "effect votes must publish the key" were missing.

**Review of the completed work (P0.1): results.** Three independent read-only reviewers reported; I checked each claim against the code before acting. Summary: the roster (#47) held up — no reviewer could make a genuine client seal to a key the server controls. The workspace governance fixes (#46) and several public claims did not fully hold. Fixed items are listed below as they land; unfixed ones are described only in general terms here (public repo etiquette, section 7) and tracked in the PR.

- **Fixed: rate-limit address spoofing behind a proxy.** `clientIp` (`server/http.js`) preferred a vendor header (`Fly-Client-IP`) over `X-Forwarded-For`; behind nginx or Caddy that header is whatever the client sends, so every request could pick its own address and skip the per-IP limits (the #46 `TRUST_PROXY` fix was undone for any deployment following the README). The header is no longer read. `TRUST_PROXY` must now be a whole number; `true` or a typo used to become 0 silently, now the server stops with a message. Unit test failed before the change.
- **Fixed: a recall could be blocked or dodged by the person it targets** (`server/workspace.js`, `shared/permissions.js`).
  - *Blocked:* counting needed the `election_committee` role *now*, so after a recall closed, an officer could remove that role from the committee and nobody could count. Counting is now authorized by membership of the vote's own committee (fixed when the vote opens); `vote.tally` is `'*'` in the matrix and the routes check the committee first.
  - *Dodged:* a recall's effect only marked roles still held, so stepping down just before the count left no `removed_by_vote_id`, and the role could be handed straight back. The effect now marks the role either way.
  - Three new tests in `test/workspace.test.js` ("a recall cannot be blocked or dodged...") failed before the change.
- **Fixed: "No" could still pass for ratification and strike votes.** Their options and rule were free (plurality allowed). They are now fixed Yes/No with majority or two-thirds, like dues and bylaws; the vote form matches. **Owner decision:** should these two also *require* the key to be published (no k-signature tally)? The existing strike-authorization test uses the signature path, so I left it allowed. Default if unanswered: leave as is.
- **Fixed: the confirmation-email caps could be sidestepped** (`server/campaign.js`). The per-campaign cap counted cards still in the database, so withdrawn cards stopped counting; the per-address cap treated `name+x@` and case variants (and Gmail dots) as new addresses; a refused request could still use up a slot; two simultaneous confirmations for one card could both send. Now: an in-memory per-campaign counter (reserved only after every check, given back if the send fails) alongside the database count; addresses are counted by mailbox (`mailboxKey`); an in-flight guard per card. Three new tests failed before the change. Threat model sentence rewritten to say what the caps do and do not stop.
- **Fixed: the founder could be led to sign a lower threshold than they chose; a trustee link could be put in the founder's seat** (`shared/roster.js`, `web/src/trustee.js`, `web/src/organize.js`).
  - The roster's `k` and `n` came from the server, and key words cover keys, not numbers. The founder's browser now remembers the plan it chose (`plan.<campaignId>` in local storage, set at creation and on "Save the plan"), and `rosterToSign` refuses a different `k`/`n` (`plan_mismatch`). On a device that does not remember it, the confirm step now states plainly "you are signing: any k of the n trustees..." (it never showed the numbers there before).
  - `EnrollPage` took the seat number from the server. New `checkEnrollment()`: a link carrying a founder check is never seat 1 (`not_founder`), and seat 1 must be the founder it names (`founder_mismatch`), checked before any key is made.
  - Unit tests; each guard mutated out makes its test fail. **Not yet covered by a browser test** (the wiring is one call each; the 15 browser tests still pass).
- **Fixed (a #46 regression): a grievance was stranded when the chief steward changed.** Working a case needs the case key (right, from #46), but a chief steward appointed after filing had none, and nothing could give them one; the page even said they could work it. New `POST /api/ws/grievances/:id/share` (`grievance.share`, `'*'`, the route requires the caller to hold the case key): the worker or a keyed steward seals the key to a current steward or chief steward. It only adds, never replaces, and it shows in the worker's access log. The case page lists who is missing a key and offers "Share this case with ..."; `canWork` now requires the key; a keyless chief gets `409 no_case_key` instead of `404` (they could already see the case exists). *Same trust limit as filing (#37):* the recipient's public key comes from the server. Tests failed before the change; unit 34, API 83, browser 15.
- **Hardened: SQLite journal mode pinned to `DELETE`** (`server/db.js`). In WAL mode one commit would append the "has voted" update and the new ballot side by side; a file switched to WAL (say with the sqlite3 shell) is now switched back on open. Unit test failed before. The `recursive_triggers` comment no longer claims to stop "anyone with SQL access" (it is per connection and guards this app's own SQL; the hash chains and device pins catch direct edits). The ballot-order test gained a rank-correlation bound. Found while checking it: the per-cast rewrite reads rows back by their random primary key, so re-inserting already scatters them and the explicit shuffle is a second layer; a "nearly sorted" shuffle mutant is therefore not detectable and was not expected to be.
- **Hardened: the `frontend trust:` tripwire** (`test/unit.test.js`, rule 9c). The old check looked for `raw.trustees` on the same line as a seal call and for `authenticate(` anywhere in the file; the reviewer showed six mutations it missed (the pre-#47 relock written over two lines, the server's list routed through a variable, `f: undefined`, link parameters in a variable, a member link without `f`). New `trustViolations()`: each sealing call must name an authenticated source directly (`sealTo.*`, or `relock` with `roster.*`/`a.*` from `rosterToSign`/`authenticate`), `sealTo` may only be assigned from `authenticate()`, the seal functions may not be aliased, and every `/j`, `/t`, `/m` link must be an object literal with a real `f`. The test also runs nine known-bad mutations of the real sources through the checker and fails if any slips past.
- **Docs truth pass: done** (task from the review's third report; a writer agent drafted it, I checked every change against the code). Corrected in `docs/THREAT_MODEL.md` (what a database copy shows on both sides, when the server holds a vote key, the founder-only phase and single-trustee powers, bearer tokens, what is logged, audit log vs ledger checks, triggers vs direct file access, reproducible builds as "last checked", what stays in browser storage), `README.md`, `site/index.html`, `docs/PROTOCOL.md` §4, `content/legal/common/data-protection.md` (draft header and `TODO(lawyer)` kept), and the app's own wording (`organize.js`, `pages.js`, `ws-help.js`, `workspace.js` bylaws template; Spanish entries rewritten, none orphaned). Notably the app said "until at least one more trustee joins, only you can open the cards" (false since #47), "not even this website" for grievances (#37 says otherwise), and "every member can recount" (only when the key is published).
- **Fixed: workspace claim links left their token in the address bar and history.** `ClaimPage` now scrubs the fragment once it has read it, like the organizing pages. The new browser assertion failed before the change.
- **Design note for #37, #43 and founding: `docs/design/workspace-trust.md`.** A proposal, not implemented: the options for an anchor of trust, a four-stage plan, and **four decisions for the owner** (anchor; what a one-officer union may do; how founding is authenticated; order of work). Default if unanswered: I do only Stage 1 items that need no protocol decision, on a branch.
- **Suites after all of the above:** unit 35, API 83, site 2, browser 15.
- **#40, part: an opened card's text is checked against its own fingerprint.** `cardTextMatches()` in `shared/verify.js`; the filing package flags a mismatching card in the roster and prints "DOES NOT MATCH" next to its hash (it printed the hash unchecked before), and the review screen counts them. A mismatch can only come from altered signing code or a bug (the encryption stops anyone else changing a card). Unit test failed before; browser 15 pass.
- **#40, part: workspace encrypted fields are bound to their row** (`server/kms.js`, `server/workspace.js`). New values are `v2.`, with additional data `column|rowId`; `v1.` values (column only) are still read. A value that does not decrypt shows as `[unreadable]` rather than crashing the page or showing someone else's data. No bulk migration: ledger rows cannot be rewritten (immutability triggers), and other rows move to `v2` when next saved; the threat model says so. The new swap test failed before the change (it showed Marco's email as Mona's). Unit 36, API 85, browser 15.
- **#40, part: trustee request signatures cover the body.** `authMsg` has a second form, `ludlow auth v2|nonce|route|scope|SHA-256(body)`, used for every trustee action (`tcall` sends the body exactly as signed; the server hashes the raw text it received, `ctx.rawBody`). A body-less signature is not accepted for trustee routes. The workspace sign-in keeps the old form (its body carries the signature). Test helper `trusteeAuth` now signs lazily, once the body is known, so the 35 existing call sites did not change. New unit and API tests; the API test fails when `authMsg` ignores the body. Unit 37, API 86, browser 15. Remaining in #40: passphrase strength.
- **#40, part: chosen passphrases must not be a simple pattern.** `passphraseOk` now also refuses fewer than 6 distinct characters, one piece repeated (`passwordpassword`), a straight run (`12345678901234`, `abcdef...`) and the same word again and again; no dictionary (that would be a dependency). The app's message says so; the threat model says there is still no dictionary check. **#40 is now done** except what needs a decision: nothing.
- **#38, part: trustees see where the release count comes from.** The trustee view of `/progress` now carries `provenance`: counted cards by each trustee's direct invitations, by members' invitations (with how many members and the most from any one), confirmed in person from group links, and from members who have since withdrawn. Counts only; members do not get it. Shown under "The lock" on the dashboard. The threat model says it makes inflation visible, not impossible. **Still open in #38 (owner's call):** capping direct invitations per member, or requiring a second person's vouch. New API test failed before; unit 38, API 87, browser 15.
- **P3.3 done: a browser test for the `committee_changed` retry.** In the "other trustees join later" journey, a signer opens the signing page in the founder-only phase and fills it in; the founder confirms the committee; the signer then presses Sign. The test checks the page got `409` then `200` without asking the person anything and that the card is k-of-n, then withdraws the card through the real API so later counts are unchanged. With the retry removed from `JoinPage`, this test fails.
- **4.6 done: `site/img/committee.png` regenerated** from the browser suite's `06c-key-words` shot (key words, per-trustee checks, and the "you are signing: any 2 of the 3" line). Alt text updated. The other site screenshots were not replaced.
- **#13 deployment guide: `docs/DEPLOY.md`.** For someone running one server for one union: who should run it (not a trustee), the master key, Docker run with the port on loopback, Caddy with access logs discarded, checking `/verify`, a consistent SQLite backup command (checked locally), updates and what not to turn on. Linked from the README. Nothing in it claims more than the code does; `docker build` itself was not run here (no daemon).
- **#44, part: small-group suppression can no longer be undone by subtraction.** When exactly one shift would be hidden, the next smallest is hidden with it (the existing test itself showed the leak: 8 people, Day 6 shown, so Night = 2). Test updated and extended to three shifts; it failed before. Still open in #44: a group that is shown can reveal a very small number of non-members; the audit log naming workers; session rows.
- **#44, part: Lock and quick exit end the workspace session on the server** (`endSession()` in `web/src/wsbase.js`, a `keepalive` logout so it completes while quick exit leaves the page). Before, the server session lived on for up to 12 idle hours after the tab forgot it. New browser assertion (the session row is deleted on Lock) failed before. Still open in #44: session rows keep member id and times while active; the audit log names workers who filed.
- **#41, part: members check who was paid, not only how much.** The finance summary now includes each non-redacted entry's salt; `checkCommitments()` (`shared/verify.js`) re-derives `H(salt|payee|memo)` and compares it with the commitment inside the hash chain; the money page warns loudly on a mismatch and says how many matched. The new API test re-encrypts a different payee (as someone with the file and the master key could) and shows the chain alone does not notice while the commitment check does. Redacted entries get no salt. PROTOCOL updated. Still open in #41: audit view paging and anchoring; results/dues/roles outside the chain; comparing heads between members.
- **#41, part: the whole audit log is checked, not only the newest page.** `/api/ws/audit` now also sends `chain` (every entry, no names), which the officer's browser verifies from the first entry and pins; the page lists 100 at a time with "Show older entries" (`?before=seq` on the server). Before, above 500 entries only the newest 500 were checked, without an anchor, and a roster view (one entry per member) could push the rest out of sight. New API test (560 entries; a rewritten early entry is caught) and a browser assertion. Still open in #41: vote results, dues plans, policy and roles outside the chain; comparing heads between members.
- **#43, part: officer elections (still behind the flag, off) name the person who gets the role.** Option labels were free text independent of `effect.memberIds`, so the winning label and the person given the role could differ. Now the server requires 2 to 12 distinct candidates who have joined the union (`not_a_member` otherwise), stores neutral labels (`Candidate 1`...) so names stay encrypted at rest, and every view (vote, tally bundle, recount, export) shows each candidate's own name. New test failed before. The flag should still stay off until an attorney signs off (CLAUDE.md rule 16).
- **#43, part: an account claimed after a vote opens does not vote in it.** Eligibility is now members whose account was claimed when the vote opened (`claimed_at IS NOT NULL`). Before, unclaimed member accounts were eligible, so whoever held their claim links could claim them mid-vote and vote. A side effect: turnout and "close when everyone has voted" no longer count accounts nobody has claimed. New test failed before; API 91, browser 15. Still open in #43: second approval for sensitive roles (design note), a members-visible feed of claims, petition deadline enforcement, reopening closed cases.
- **P3.7, part: GitHub Actions pinned to commit SHAs** (with the version in a comment, which Dependabot keeps up to date), and a new CI job, **Reproducible build**, builds `app.js` locally and in the Docker image's build stage and fails if the hashes differ. This is the first automated check of the "reproducible builds" claim; its first run on this PR is the verification (no Docker here).
- **#39 research: `docs/research/ballot-secrecy.md`.** Recommendation on what to promise (secrecy from members, officers and a database copy; stuffing is caught) and what not to (secrecy against an operator running modified code; receipts proving your ballot was counted; coercion resistance once the key is published), plus an order of work: an honest warning now; an anonymous submission channel with blind tokens next (needs a cryptographer); a threshold tally later; *not* a ballot-hash self-check while keys are published. Step 1 is done: the tally page now warns that once the key is published anyone who kept their encrypted ballot can prove how they voted. **Correction to my earlier PR comment:** I recommended that ratification and strike votes *require* the key to be published; this research says the opposite (those are the votes where coercion matters), so my recommendation is now **no, keep it optional**.
- **#43, part: a missed petition deadline is visible to every member.** Petitions now report `overdue` (qualified, and the 14 days in the bylaws have passed); the Votes page shows a red badge and says to ask the committee why. The server cannot open the vote itself (the ballot key is made in a committee browser). **Owner decision:** should any member (or any signer) be allowed to open an overdue petition's vote? Default: no, visibility only. New test failed before; API 91.
- **#44, part: the audit log no longer names the worker who filed a case.** `grievance.filed` has no actor; `grievance.opened` and `grievance.shared` point at the case, not the worker's member record. The worker's access log now also includes what others did on the cases they filed, so they still see who opened their case. New assertion (no grievance entry in the officers' audit chain carries the worker's id) failed before. **Still open:** entries written before this change; the officer export lists which members hold each case's key (so it still shows the worker); session rows.

**Second review, of this session's own changes** (one independent reviewer over everything above; findings checked by hand):
- **Fixed: the payee check skipped entries without a salt,** so a swap could be hidden by also dropping the salt or damaging the memo. A visible entry without a salt now fails.
- **Fixed: row binding could be dodged with old-form values,** and member names and emails would never have moved to the new form. The server now re-encrypts every old-form member and spending field to its row at start-up (one transaction, idempotent) and refuses the old form for them afterwards; only ledger entries (immutable) keep it. Test: old-form values written, server restarted on the same database, values are `v2` and read correctly, and an old-form value pasted in afterwards shows as unreadable. Failed before.
- **Fixed: a worker sharing their own case was named as the actor** in the audit log. Also fixed a flaky unit test I had introduced (about 3% of runs; see the commit).
- **4.7 Spanish: the whole interface is translated (first draft).** 655 new entries in `web/src/es.js` (a translator agent drafted them; I checked every placeholder survives, there are no duplicate keys, and the browser suite, including the Spanish signing flow, passes). New unit test: every Spanish entry must belong to an English sentence the code still uses (rewording English used to strand translations silently); it caught one stale entry, removed. README and site now say the interface is in Spanish as a first draft and most legal pages are English only. **For the native reviewer (#10)**, terms the translator was unsure of: "activar tu cuenta" for claim your account; "quien fundó la campaña" for founder; "tarjetas desconocidas" for disavowed cards; "libro de cuentas" / "entrada de reversión"; "días naturales" for calendar days; "carta de exigencia" for demand letter; and a clash between "queja" for grievance and "presentar una queja" for filing a charge. Not translatable without a code change: the custom threshold marker (a template string in `packs.js`) and the discreet tab title "Notes".
- **Fixed (review of this session, low):** what `authenticate()` and `rosterToSign()` return is now deeply frozen, so browser code cannot swap a seat in after the check (the tripwire could not see that); a trailing dot (`gmail.com.`) no longer escapes the per-mailbox cap, and address literals (`[1.2.3.4]`) are refused; small-group suppression keeps hiding groups until the hidden ones total at least 5 (two hidden groups of 1 could still be recovered). Each with a test that failed before.
- **Fixed (review of this session, low-medium): the audit rows on screen are the ones that were checked.** The page verified `chain` but listed `entries`; a server could show different rows. `auditRows()` (`shared/verify.js`) builds each row from the chain entry with the same seq and takes only the actor's name from the page, and only when it names the same actor; a row the chain lacks is marked "not in the checked log". Unit test.

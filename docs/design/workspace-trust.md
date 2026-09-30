# Design note: whose keys the workspace trusts

*Status: proposal for the maintainer to react to (30 September 2026). Nothing here is implemented yet. Covers [#37](https://github.com/ChrisRyanWill/project-ludlow/issues/37) (workspace keys), the one-officer part of [#43](https://github.com/ChrisRyanWill/project-ludlow/issues/43), and unauthenticated founding. These three are one problem: the workspace has no anchor of trust.*

## 1. The problem in one paragraph

On the organizing side, a browser seals only to keys it can check: the founder's, checked against the `f` value in its link, and the ones the founder signed in the roster (`docs/PROTOCOL.md` 1a). The workspace has no such anchor. Every public key a member's browser seals to comes from the server:

- the chief stewards' keys, for a new grievance;
- a steward's key, for an assignment or a hand-over;
- the election committee's keys, when a vote is opened;
- the vote's own public key, when a ballot is cast.

A server that lies, running the genuine code, can substitute its own keys and read what is sealed to them. That covers new grievances, and ballots too: a ballot sealed to a substituted vote key can be read, then re-sealed to the real key before it is stored. Separately, **anyone can create a workspace** (`POST /api/ws` needs no proof that it comes from a campaign). **One officer can add accounts they control** and give them roles, because the officer's own browser makes the claim links. Two-officer spending approval and a committee-signed tally then protect less than they appear to.

## 2. Who we defend against

| Adversary | Can | Cannot |
|---|---|---|
| **A lying server** (a hacked host, or an operator under pressure) | Read and write every row; answer any API call as it likes. | Change the JavaScript the browser runs (out of scope: see the threat model); read URL fragments; forge a signature by a key it does not hold. |
| **One dishonest officer** | Everything an officer's role allows, including making claim links and granting roles. | Act as a second, different person whose key they do not hold. |
| **A database copy** | Everything at rest. | Already covered in the threat model; not changed here. |

The goal matches #47: *a genuine browser never seals to a key that no trusted person vouched for*. The second goal is that *no single officer can create the second signature a safeguard asks for*.

## 3. Options for the anchor

| Anchor | How members learn it | For | Against |
|---|---|---|---|
| **A. The campaign founder** (trustee 1), who already has an authenticated key | Claim links carry the campaign's `f` | Reuses #47 almost exactly; one person to check | The founder may not be an officer; one person is the single point of betrayal (as today for cards) |
| **B. k founding trustees** sign together | Claim links carry a hash of the trustees' signing keys | Nobody can betray alone | Needs k people at founding; heavier ceremony |
| **C. The founding officers** sign the first workspace roster | Claim links carry a hash of the founding officers' keys | The people who run the union are the anchor | Their keys do not exist until they claim, so founding becomes two steps |

**Recommendation: C, bootstrapped from A.** The campaign founder's browser (already authenticated) creates the workspace and signs a short founding statement: the workspace id, and the claim-token hashes of the founding officers. After the founding officers claim and check each other's key words in person, **two of them** sign the **workspace roster**: every role holder's `{memberId, role, boxPublicKey, signPublicKey}`. From then on the officers are the anchor, and the founder's part ends.

## 4. What changes, in stages

Each stage is useful alone and has the same kind of tests as #47: unit tests that play every move a lying server has, plus browser tests that alter rows and watch the genuine app refuse.

**Stage 1 (cheap, no protocol change)**
- Each device pins the box and sign keys of every role holder it has sealed to (`pin.<wsId>.<memberId>`). A changed key produces a loud warning, and nothing is sealed until the person confirms.
- Key words for chief stewards, stewards and the election committee are shown on their own screens and in the member's filing view, so they can be compared in person.
- The vote's key fingerprint appears on the ballot page and in the committee's count view. The member who opens a vote must be on its committee.
- A members-visible **changes feed**: every account added after founding and every role grant, with who did it.
- Honest limit: pinning catches a key that changes, not one that was false from the start.

**Stage 2 (the workspace roster)**
- Founding is signed by the campaign founder (section 5), and claim links carry that founder's `f`.
- Two founding officers sign the workspace roster after checking key words. The server stores it but cannot forge it.
- A shared `authenticateWorkspace(raw, f)` (the analogue of `shared/roster.js`) decides what a browser may seal to: role holders in the signed roster only. A tripwire test, like `frontend trust:`, fails if any workspace code seals to the server's list.

**Stage 3 (signed role changes; closes the one-officer gap)**
- A role grant or removal after founding is a statement signed by **two different officers already in the roster**, or it is the result of a vote.
- A sensitive grant (`officer`, `treasurer`, `chief_steward`, `election_committee`) also waits a notice period. Members see it in the changes feed and can petition to stop it.
- Members' browsers verify the chain from the founding roster before sealing.
- A union with only one officer can still add stewards and ordinary members, but it needs a vote to add a second officer. **Decision needed**, below.

**Stage 4 (vote keys)**
- Real joint key generation needs a threshold protocol, and `CLAUDE.md` rule 9 forbids writing primitives. Instead:
  - the opener, who must be on the committee, signs `{voteId, votePublicKey, committee}`;
  - each committee member's browser checks, when counting, that its share and the others rebuild a key matching `votePublicKey`, and signs that it did;
  - voters' browsers seal only to a vote key signed by a roster-authenticated committee member.
- What stays true, and should be stated plainly: the opener's browser holds the whole key for a moment.

## 5. Founding a workspace

Today the only check is `confirmedPublic: true`, and one request may carry up to 10 MB and 3,000 members.

| Option | For | Against |
|---|---|---|
| **Signed by the campaign founder** over `{workspaceId, campaignId, …}`, checked against the campaign's seat 1 | Real proof; needed for Stage 2 anyway | Links a workspace to a campaign in the database, which a copy then shows. The campaign side is otherwise zero-knowledge. |
| **An operator's founding code** (`FOUNDING_CODE`, optional) | Trivial; right for a self-hosted server with one union | Not a proof about the campaign |
| **Smaller caps** (for example 500 members per request, adding more later) | Limits storage abuse | Does not stop impersonation |

**Recommendation:** the founder's signature, sent with the request and checked once, **without storing the campaign id**. The server keeps only the fact that the check passed, so a database copy does not link the two. Add the optional operator code for public-facing servers.

## 6. Decisions for the maintainer

1. **The anchor:** C bootstrapped from A (recommended), or A, or B?
2. **A single-officer union:** should adding a second officer need a vote (recommended, with a clear explanation in the app), or should a notice period be enough?
3. **Founding:** founder's signature without storing the campaign link (recommended), plus the optional operator code?
4. **Order of work:** Stage 1 now (recommended: it is small and useful), then 2 and 3 together, then 4?

Until these are decided, the cloud session will do only Stage 1 items that need no protocol decision, and only on a branch.

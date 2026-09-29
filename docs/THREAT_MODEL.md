# Threat model

**Adversaries:** an employer who wants to learn who signed, infiltrate the campaign, or subpoena the operator; someone who compromises the server or its database; a legal demand on the operator or the email provider; a rogue or coerced trustee or officer; a faction inside a union; and, over time, plain financial misconduct.

## What the design protects

| Threat | Protection |
|---|---|
| Database dump or subpoena of the campaign system | Reveals that campaigns exist, card counts, timestamps and public keys. Union, employer, and every card field are ciphertext the server has no key for. Deleted cards are zeroed on disk (`secure_delete`). |
| Server compromise | Same as above. The server never holds a card key, a trustee key, a vote key, or a grievance key. |
| One rogue trustee | Cannot open cards alone once the committee is complete (any k of n are needed). |
| Trustees opening the cards too early | **A release number, set when the campaign is created, is enforced by the server:** it will not hand over the sealed cards until that many are signed *and* confirmed, and a disavowed or withdrawn card closes the gate again. The cards live only on the server, so trustees who hold keys still have nothing to decrypt. Raising the number is free; lowering it takes k trustees agreeing on the same value. Signers and members can see the number. |
| Leaked or forwarded invite link | Direct links are single-use and auto-vouched; group links expire and their cards only count once the link's creator confirms the signer in person, with a 5-try lockout. Trustees can pause a campaign instantly. |
| Logs | Only method, route *pattern*, status and duration are ever logged (test-enforced). No bodies, queries, headers, tokens or IPs. |
| Request forgery, replay | Challenge-response signatures are single-use, expire in 2 minutes and name the action. |
| Employer or officer reads member data | Workspace personal fields are encrypted at rest; every look at someone's record is logged where they can see it. Case content is end-to-end encrypted to the people assigned. |
| Vote tampering, learning how someone voted | Ballots have no voter reference or timestamp; the counting key is split among the election committee; the server refuses a tally that does not match when the key is published; every member can recount. |
| Financial misconduct or a rewritten history | Two-officer approval above a threshold; immutable ledger (DB triggers); hash chains that each member's browser verifies and pins. |
| Officers entrenching themselves | Petition-forced votes and recalls, defined as bylaws data that only a member vote can change. |
| Someone looking over a shoulder | Quick exit, neutral tab titles, no persistent login (workspace sessions live in memory). |

## Honest limits

- **The confirmation email.** The law needs it. For that moment the server sees the signer's email and card fields, sends the message, and discards them. The email provider keeps its own delivery logs.
- **Hosting.** The host may log IP addresses at the network edge.
- **The code is delivered by the server.** A compromised server could send malicious JavaScript. Mitigations: the fingerprint check on `/verify` (trustees should compare it with each other before opening cards), a strict CSP, no third-party code, and the option to self-host. This is the largest known weakness.
- **The release lock is enforced by the server, not by mathematics.** It stops trustees, who hold keys but not the sealed cards. It does **not** stop an operator who can read the database directly, and it binds nothing if the trustees also run the server. Host the server somewhere no trustee controls if you want it to bind them. Once the number is met, any k trustees together can open the cards; the software cannot judge whether that is wise.
- **Founder-only phase.** A campaign can start with one person. Until every planned trustee has joined, each card is sealed to the founder alone, so one person, or anyone who steals their key file and passphrase, can open them. The lock still applies, and the app says so plainly. Add trustees soon: when they have all joined, the founder re-locks the early cards so that k of n are needed. If too few trustees can later cooperate (lost keys), those cards cannot be recovered.
- **The release number is visible to the server.** It is a count (by default a majority of the group), which lets a determined adversary estimate the size of the unit.
- **A secretly hostile vouched member** sees the card count. Anyone with a member link can act as that member.
- **Traffic correlation.** An operator watching live traffic could try to match a request to a ballot insertion. Timestamps and order are not stored, but perfect unlinkability against the operator is out of scope.
- **Workspace personal data is readable by the server** (it must send mail and print notices). An attacker who steals both the database and `WORKSPACE_MASTER_KEY` reads it.
- **Small unions:** with very few members, counts and shifts are inherently identifying; small-group suppression starts at 5.
- **Once names go to an employer or an agency they are no longer secret.** The encryption protects the organizing period.
- Rate limits and login challenges are held in memory, so run one instance.
- The spreadsheet exports neutralise formula injection, and PDFs replace characters the standard fonts cannot draw with `?` (the CSV keeps full Unicode).
- Not yet audited by an independent party.

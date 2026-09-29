# Build Prompt V2: Union Workspace (Running a Healthy Union)

This document extends the MVP described in `BUILD_PROMPT.md` / `docs/SPEC.md`. **Do not start V2 until every MVP phase is complete and its tests pass.** Everything in the MVP's `CLAUDE.md` rules still applies unless this document explicitly changes it.

V2 adds the **Union Workspace**: the tools a newly public or recognized union uses to govern itself democratically, bargain its first contract, represent members, manage money transparently, meet its legal obligations, and — where the union chooses — work constructively with management.

Guiding idea: **software can't make a union good, but it can make the good behavior easy.** Transparency by default, easy participation, no missed deadlines, fair treatment of every worker, and full ownership of the union's own data.

---

## 0. First actions

1. Re-read `CLAUDE.md`, `docs/SPEC.md`, and `docs/THREAT_MODEL.md`.
2. Create `docs/SPEC_V2.md` containing this entire document verbatim.
3. Append **Section 2 (V2 rules)** to `CLAUDE.md` under a heading `## V2 Union Workspace rules`.
4. Add a section `## V2: Union Workspace` to `docs/THREAT_MODEL.md` from Section 3.
5. Begin **Phase V0** (Section 13). As before: one phase at a time, run all tests, commit, then **stop and summarize** what was built, what was tested, and open questions. Wait for my approval before continuing.

Ask rather than guess. If a requirement looks legally or technically wrong, say so and propose an alternative.

---

## 1. Product summary

### 1.1 Two systems, one codebase
- **Campaign system (MVP):** secret, zero-knowledge card collection. Unchanged.
- **Union Workspace (V2):** a separate module for a union that has **already gone public**. It necessarily holds a real membership roster (the union must mail election notices, collect dues, and represent people by name), so it uses a different privacy model: named accounts, role-based access, encryption at rest, audit logs, and end-to-end encryption for the most sensitive records.

The two systems must share as little as possible. No campaign table may be joined to any workspace table. The only bridge is the **Founding flow** (Section 5), run by trustees in the browser.

### 1.2 Workspace stages
| stage | meaning | what's available |
|---|---|---|
| `public_prerecognition` | the union has gone public (demand sent or petition filed) but is not yet recognized or certified | membership, governance, meetings, surveys, communications, voluntary dues, treasury, compliance |
| `recognized` | voluntarily recognized, certified by the NLRB, or under a bargaining order | everything above **plus** bargaining, contract library, grievances, and the labor–management module |

Officers set the stage manually, attaching a note or document reference (e.g., "NLRB certification, case 27-RC-XXXXXX"). The labor–management module must be impossible to enable before `recognized` (joint committees with a non-recognized group can create legal risk under NLRA Section 8(a)(2)).

---

## 2. V2 rules (append to CLAUDE.md)

### Privacy and security
1. **Never create a workspace from a campaign that hasn't gone public.** The Founding flow must show a blocking warning explaining that names will become readable to officers and stored (encrypted at rest) on the server, and require a checkbox confirming the union has already gone public.
2. **Personal data in the workspace is encrypted at rest at the application layer** using envelope encryption: each workspace has a data key, itself encrypted by a master key from `WORKSPACE_MASTER_KEY` (later: a cloud KMS). Encrypted fields: names, emails, phones, home addresses, job titles, notes. A database dump alone must not reveal them.
3. **End-to-end encrypted records:** grievance notes and attachments, hardship-fund applications, and anything marked "confidential." Only the users assigned to that record can decrypt them. The server never holds a key that opens them.
4. **Secret ballots must be unlinkable.** No table, column, log line, or timestamp may connect a voter to their ballot content (Section 8).
5. **Every read of a member's personal data by another user is audit-logged** (who, what record, when). Members can see the access log for their own record.
6. **Management guest accounts may only ever access the labor–management module.** They can never see the roster, dues status, grievances, votes, finances, meeting minutes, or surveys. Enforce in the authorization layer *and* prove it with tests.
7. **Representation is never gated by dues.** A union must represent everyone in the bargaining unit fairly (duty of fair representation). Grievance intake, steward help, the contract library, and general communications must be available to every unit employee regardless of membership or dues status. Voting eligibility follows the bylaws and law, not a subscription.
8. **The union owns its data.** A complete export (Section 11) must always work, and officers can delete the workspace entirely.
9. **No AI features that send member data to third parties.** No analytics, telemetry, or error tracking that receives request data (MVP rule stands).
10. First-party, `HttpOnly`, `Secure`, `SameSite=Strict` session cookies are allowed in the workspace for authenticated sessions. Still no tracking cookies of any kind.

### Legal and governance
11. All legal and procedural content (bylaws templates, election procedures, compliance calendar text, Weingarten card, training modules) lives in `/content/legal/v2/` with the header `DRAFT — REQUIRES REVIEW BY A LICENSED LABOR ATTORNEY BEFORE REAL-WORLD USE`. Mark uncertainty with `TODO(lawyer):`.
12. The platform never files government forms, sends anything to the employer, or submits anything to the NLRB or Department of Labor automatically. It prepares drafts and data for humans.
13. **Officer elections held online are behind a feature flag (`ONLINE_OFFICER_ELECTIONS=false` by default)** with an in-app notice that federal rules for electronic officer elections are strict and an attorney must approve its use. The default officer-election workflow supports **mail ballots**: generating mailing lists, notices, printed ballots, and a tally-entry interface for the election committee.
14. Dues changes must be linked to a completed secret-ballot vote record before they can take effect (Section 8.4).

### Engineering
15. Every permission rule is data-driven (Section 6) and covered by an automated permission-matrix test.
16. Every module ships with tests, and the MVP plaintext-leak test is extended to workspace data (Section 12).

---

## 3. V2 threat model (append to docs/THREAT_MODEL.md)

**New adversaries and risks:**
- Employer or management guest attempting to see member data, grievances, votes, or finances.
- A rogue or careless officer misusing the roster.
- Election tampering or a union faction trying to see how members voted.
- Financial misconduct (the most common way unions lose members' trust).
- Database compromise or subpoena.

**Protections:**
- Envelope encryption at rest for personal fields; E2E encryption for grievances, hardship applications, and confidential records.
- Role-based access with least privilege; audit logs visible to officers and to the affected member.
- Unlinkable secret ballots; election committee role separate from candidates; published results with turnout.
- Two-officer approval for disbursements above a threshold; member-visible financial summaries; immutable ledger entries (corrections are new entries, never edits).
- Hard isolation of management guest accounts.

**Known limitations (state honestly on the workspace's "How your data is protected" page):**
- The server can decrypt at-rest-encrypted fields (it needs to, for mailing lists and emails). A server compromise with access to the master key exposes them.
- A server operator observing traffic in real time could attempt to correlate a voter's request with a ballot submission. Mitigations are described in Section 8; perfect unlinkability against the operator is out of scope.
- Officers necessarily see the roster.

---

## 4. Authentication and accounts

- **Sign-in:** email magic link (single-use, 15-minute expiry, token in URL fragment, same pattern as MVP) plus optional **passkeys (WebAuthn)**.
- **Officers, treasurer, election committee, and chief steward must use a passkey** (second factor enforced on role assignment).
- **Device keys for E2E features:** users who need E2E access (stewards, hardship committee, officers) generate a libsodium box keypair in the browser. The private key is stored in IndexedDB encrypted with a passphrase-derived key (Argon2id, same parameters as MVP key files), with a downloadable encrypted backup file. Public keys are stored on the server.
- **Sessions:** server-side session table, 12-hour idle timeout, 30-day absolute, revoke-all-sessions button per user.

---

## 5. Founding flow (campaign → workspace)

Run by trustees during or after the MVP unlock ceremony, entirely in the browser:

1. After decrypting cards, the unlock page offers **"Start your union workspace."**
2. Blocking warning (Rule 1). Checkbox: "We have already gone public."
3. Trustees choose the workspace stage (`public_prerecognition` or `recognized`), union name, employer, unit description, and the **founding officers** (interim roles until the first election under the bylaws).
4. The browser sends the roster (name, email, phone, job title, shift/department, preferred language) to the workspace API over TLS, where it is encrypted at rest. Card signers are marked as **founding members**.
5. Each founding member receives an **opt-in invitation email**: "Your union has started its workspace. Claim your account." Unclaimed invitations expire after 30 days; the roster entry remains (the union still represents them).
6. Trustees are prompted to **destroy the campaign** afterward (MVP destroy flow).

A workspace can also be created from scratch (for unions that organized without the MVP), with a CSV roster import.

---

## 6. Roles and permissions

### 6.1 Roles
| role | description |
|---|---|
| `unit_employee` | anyone in the bargaining unit, member or not. Can view contract, file grievances, see announcements, update own profile. |
| `member` | unit employee who has joined the union per the bylaws. Adds: voting, meetings, surveys, member financial summary. |
| `steward` | assigned to shifts/locations; handles grievances assigned to them. |
| `chief_steward` | assigns grievances; sees all grievance metadata; E2E access to all grievances. |
| `officer` | president, vice president, secretary, etc. Manages governance, communications, roster. |
| `treasurer` | manages dues, ledger, compliance reports. |
| `election_committee` | runs elections; cannot be a candidate in the election they run. |
| `bargaining_committee` | works in the bargaining module. |
| `hardship_committee` | reviews mutual-aid applications (E2E). |
| `management_guest` | employer representative; labor–management module only. |

Users can hold multiple roles, except the conflicts enforced below.

### 6.2 Rules
- Permissions live in `packages/shared/permissions.ts` as a single matrix of `role × action × resource`, consumed by middleware on every route.
- **Conflicts enforced in code:** a candidate in an election cannot hold `election_committee` for that election; `management_guest` cannot hold any other role; a treasurer cannot approve their own reimbursement.
- Role assignments and removals are audit-logged and shown in a member-visible "Who holds what role" page.

---

## 7. Modules

### 7.1 Membership and roster
- Records for every unit employee: encrypted personal fields, membership status (`unit_employee`, `member`, `former`), join date, shift/location, preferred language, communication preferences, **home mailing address** (needed for mailed election notices; optional field with explanation).
- Member self-service profile: view/edit own info, see own dues status, see access log for own record, download own data.
- Officer roster view with filters (shift, location, language, membership status) and the **coverage map** (Section 7.7).
- CSV import/export (export is audit-logged).

### 7.2 Governance: bylaws
- **Bylaws builder** from templates in `/content/legal/v2/bylaws/`: guided questions (officer roles and terms, election timing, quorum, how strikes are authorized, how dues are set, steward selection, amendment process, conflict-of-interest rules, financial controls like two-signature approvals).
- Output: versioned bylaws document. Every change is an **amendment proposal** with a visible diff (use a text diff library), discussion period, and a ratification vote (Section 8).
- Officer registry: who holds each office, term start/end, automatic reminders 120 and 60 days before terms expire to begin election preparations.
- Generates a PDF of current bylaws for filing with the union's initial Department of Labor registration (human files it).

### 7.3 Meetings
- Schedule meetings (general, committee, steward), agenda builder, attendance (self check-in link or officer-recorded), motions and recorded outcomes (voice/hand votes recorded as counts), minutes editor, and publication to members.
- Each meeting can have multiple language versions of agenda and minutes (entered by humans; no machine translation sent to third parties).
- Quorum check against bylaws.

### 7.4 Surveys
- Survey builder: multiple choice, ranking, scale, free text. Option for **anonymous** surveys (same unlinkability approach as ballots, Section 8.2).
- Results aggregation with **small-group suppression**: any breakdown (by shift, location, etc.) with fewer than 5 respondents is hidden, so individuals can't be identified.
- Bargaining-priorities survey template included.

### 7.5 Bargaining (stage `recognized` only)
- **Bargaining workspace** for the bargaining committee: contract articles as a list; for each article, a thread of proposals (union or employer), each with text, date, status (`open`, `countered`, `tentatively_agreed`, `withdrawn`), and version diffs.
- **Tentative agreement (TA) tracker:** progress across all articles.
- **Member updates:** committee publishes bargaining updates (approved by the committee chair) to all unit employees.
- **Contract assembly:** when all articles are TA'd, assemble the full contract text and open a **ratification vote** with a plain-language summary of changes.
- Bargaining notes are visible only to the bargaining committee and officers.

### 7.6 Contract library (stage `recognized` only)
- Ratified contract stored as structured articles and sections with Postgres full-text search.
- "Ask the contract" is **search only** in V2 (no AI).
- **Calculators** driven by a JSON configuration officers maintain (wage steps, differentials, overtime rules, leave accrual). Each result shows the contract section it came from and "The contract language governs."
- **Share link:** officers can create a read-only public link to the contract for supervisors and new hires. Revocable.
- Contract term tracking with reminders before expiration (bargaining should start well ahead).

### 7.7 Stewards and grievances (stage `recognized` only; intake open to all unit employees)
- **Intake:** any unit employee (member or not) can submit an issue: what happened, when, who was involved, which contract article they think applies (optional), and desired outcome. Content is E2E encrypted to the chief steward(s) on submission.
- **Assignment:** chief steward assigns a steward; the record's content key is re-sealed to the assigned steward.
- **Step workflow with deadlines:** officers configure the grievance procedure from the contract (steps, time limits, calendar vs. business days, who must be notified). The system computes deadlines, shows countdowns, and sends escalating reminders (7 days, 3 days, 1 day, day-of) to the assigned steward and chief steward. Deadline math has thorough unit tests, including weekends and configured holidays.
- **Informal resolution step:** optional first step where steward and supervisor try to resolve it early; recorded like any other step.
- **Fair representation log:** every intake must end with a recorded decision (`pursue`, `resolved_informally`, `not_pursued`) and a reason, and the worker must be notified. The system blocks closing a case without both. This protects workers and protects the union from duty-of-fair-representation claims.
- **Outcomes** recorded; aggregate stats (counts, average resolution time, by article) available to officers without exposing content.
- **Weingarten card:** a page and printable/saveable card explaining the right to request a union representative in an investigatory interview that the worker reasonably believes could lead to discipline, and what to say. From `/content/legal/v2/weingarten.md`.
- **Coverage map:** grid of shifts × locations showing how many stewards cover each; gaps highlighted.
- **Steward training:** Markdown modules in `/content/training/` with completion tracking.

### 7.8 Treasury and dues
- **Stripe Connect** (Express or Standard) account **owned by the union**, onboarded by the treasurer. Funds go directly to the union's bank account. The platform takes no cut.
- Dues plans configured per bylaws (flat or tiered). Members start, change, or cancel dues themselves at any time.
- **Ledger:** every receipt and disbursement, categorized to match Department of Labor LM report categories. Entries are immutable; corrections are reversing entries. Stripe payouts reconcile automatically via webhooks (verify webhook signatures).
- **Disbursements:** request → approval → paid. Amounts above a bylaws-configured threshold require two officer approvals. Receipts/invoices attached. Nobody approves their own request.
- **Budget:** annual budget vs. actuals.
- **Member financial summary:** members see monthly totals by category, current balances, and the budget — transparency by default.
- **Exports:** CSV and PDF reports, plus a pre-filled data sheet mapped to the relevant annual Department of Labor financial report (LM-2, LM-3, or LM-4, depending on annual receipts). The treasurer files it.

### 7.9 Compliance calendar
Tasks with due dates, owners, and reminders, generated from the workspace's stage, fiscal year, and finances. Include at least:
- Initial Department of Labor registration (Form LM-1) with constitution and bylaws, due within 90 days of the union becoming subject to the LMRDA.
- Annual financial report (LM-2/3/4) due within 90 days after fiscal year end.
- Officer and employee **fidelity bonding** for those who handle funds, sized from the prior year's funds handled.
- Annual IRS filing for the union's tax-exempt organization (990 series, depending on size), and the tax-exemption application if not yet done.
- Officer election due dates per bylaws (local officer elections at least every three years).
- Preservation of election records for one year after each election.
- Contract expiration and bargaining start reminders.

Put every legal threshold and deadline in `/content/legal/v2/compliance.md` with a `TODO(lawyer)`/`TODO(accountant)` check, and load them from configuration rather than hardcoding.

### 7.10 Communications
- Announcements (email + in-app), targeted by role, shift, location, or language, with per-language versions.
- Weekly digest option. Members control preferences; unsubscribe always works (except legally required notices like election notices, which are sent by mail as well).
- Email provider tracking disabled (MVP rule).

### 7.11 Hardship / mutual-aid fund
- Members apply with a short form; application content E2E encrypted to the hardship committee.
- Committee reviews, decides by recorded vote, and approved grants flow into a ledger disbursement (amount and category only in the ledger; no personal details).
- Rules and limits configured per bylaws.

### 7.12 Labor–management module (stage `recognized` only)
- **Joint committees** (e.g., safety, scheduling, training) with union members and management guests. Each committee has an agenda, meeting notes shared by both sides, and a **shared issue log** (issue, proposed fix, owner, status).
- **Early resolution channel:** a steward can invite a supervisor to discuss a specific issue before it becomes a formal grievance. Only what the steward chooses to share is visible to the supervisor.
- **Shared metrics:** the union may publish selected aggregate numbers (e.g., turnover, safety incidents reported, training completion). Nothing is shared unless an officer explicitly publishes it.
- **Contract share link** (Section 7.6).
- Management guests are invited by an officer, must use a passkey, and can be removed at any time. Everything they can see is listed on a page visible to all members ("What management can see").

### 7.13 Union health dashboard
For officers (and optionally published to members): membership rate in the unit, dues participation, steward coverage, grievance average resolution time and deadline misses, meeting attendance, vote turnout, survey response rates, upcoming compliance tasks. Show trends over time. Aggregates only; small-group suppression applies.

---

## 8. Voting system

### 8.1 Vote types
`ratification` (contract), `bylaws_amendment`, `dues_change`, `strike_authorization`, `officer_election`, `general`. Each vote defines: eligible voter rule (from bylaws; usually members in good standing), options or candidates, open/close times, required threshold (majority, two-thirds, etc.), and whether it is secret (always secret for `officer_election`, `dues_change`, `strike_authorization`, and `ratification`; configurable for `general`).

### 8.2 Secret ballot design (online)
1. When a vote opens, for each eligible voter the server creates a row in `vote_participation` (`vote_id`, `member_id`, `has_voted=false`).
2. When a voter casts a ballot, in a single transaction:
   - verify eligibility and `has_voted=false`;
   - set `has_voted=true` (no timestamp column, or date only);
   - insert the ballot choice into `ballots` (`id` random UUID, `vote_id`, `choice_ciphertext`) with **no voter reference and no timestamp**.
3. Ballot choices are encrypted to the **election committee's** vote key (libsodium sealed box to a key generated for that vote; private key split among committee members with Shamir, k-of-n, as in the MVP). Tallying happens in the browser when the committee unlocks after the vote closes.
4. The voter receives a **receipt code** (random, shown once) stored alongside their ballot as a hash, so they can later confirm their ballot was counted in the published list of receipt hashes — without revealing their choice.
5. Logs must not record ballot submissions with user identifiers. The ballot endpoint logs only status codes.
6. Results page: counts per option, turnout, threshold met or not, list of receipt hashes, committee certification.

### 8.3 Officer elections
- Default workflow is **mail ballot support** (Rule 13): nominations period, candidate list, generation of election notice mailing list (home addresses) and printable notice/ballot PDFs, and a tally-entry screen where the election committee records counts, with two committee members confirming.
- Online officer voting uses Section 8.2 but only when `ONLINE_OFFICER_ELECTIONS=true`.
- Candidates can request the mailing of campaign literature through the union (a request-tracking feature; the union handles it equally for all candidates). Track requests and fulfillment dates.
- Election records (ballots, tallies, notices) are preserved read-only for one year after the election, then eligible for deletion.

### 8.4 Dues changes
A dues plan change requires `approved_by_vote_id` referencing a closed, passed `dues_change` secret-ballot vote. Enforce in the API.

---

## 9. Data model (additions)

All personal fields marked 🔒 are encrypted at rest (envelope encryption). Fields marked 🔐 are end-to-end encrypted. No workspace table references any campaign table.

- `workspaces` (id, stage, union_name, employer_name, unit_description, fiscal_year_start, data_key_encrypted, created_at)
- `users` (id, email 🔒, email_lookup_hash (keyed HMAC for login lookup), created_at)
- `passkeys`, `sessions`, `magic_links` (token_hash, expires_at)
- `device_keys` (user_id, box_public_key, created_at, revoked_at)
- `members` (id, workspace_id, user_id nullable, legal_name 🔒, phone 🔒, home_address 🔒, job_title 🔒, shift, location, preferred_language, membership_status, joined_at, founding_member bool)
- `role_assignments` (workspace_id, user_id, role, scope jsonb, assigned_by, assigned_at, removed_at)
- `audit_log` (id, workspace_id, actor_user_id, action, resource_type, resource_id, created_at) — append-only
- `bylaws_versions` (id, workspace_id, version, content, ratified_by_vote_id, created_at)
- `amendment_proposals` (id, workspace_id, base_version, proposed_content, status, vote_id)
- `offices` (id, workspace_id, title, holder_member_id, term_start, term_end)
- `meetings`, `meeting_agenda_items`, `meeting_attendance`, `motions`, `minutes` (with language variants)
- `surveys`, `survey_questions`, `survey_participation`, `survey_responses` (responses unlinkable when anonymous)
- `votes`, `vote_options`, `vote_participation`, `ballots`, `vote_committee_keys`, `vote_results`
- `bargaining_articles`, `proposals`, `bargaining_updates`
- `contracts`, `contract_sections` (full-text index), `calculator_configs`, `contract_share_links` (token_hash)
- `grievances` (id, workspace_id, submitted_by_member_id, assigned_steward_user_id, status, current_step, article_ref, content_ciphertext 🔐, content_nonce, sealed_keys jsonb 🔐, decision, decision_reason 🔐, worker_notified_at, created_at, closed_at)
- `grievance_steps` (grievance_id, step_number, due_at, completed_at, outcome)
- `grievance_procedure_configs` (workspace_id, steps jsonb, holidays jsonb)
- `stewards_coverage` (workspace_id, steward_user_id, shift, location)
- `training_modules`, `training_completions`
- `dues_plans`, `dues_subscriptions` (Stripe IDs only), `ledger_entries` (immutable), `disbursement_requests`, `disbursement_approvals`, `budgets`, `attachments`
- `compliance_tasks` (workspace_id, type, due_at, owner_user_id, status, notes)
- `announcements` (+ language variants), `communication_prefs`
- `hardship_applications` (content 🔐, decision, ledger_entry_id)
- `jm_committees`, `jm_committee_members`, `jm_issues`, `published_metrics`, `early_resolution_threads`

Use Drizzle migrations. Add DB-level constraints where possible (e.g., `ballots` has no FK to users; `ledger_entries` has no UPDATE/DELETE grants for the app role — enforce with a Postgres trigger that rejects updates and deletes).

---

## 10. Legal and content drafts (`/content/legal/v2/` and `/content/training/`)

Each with the required draft header:
- `bylaws/` — modular bylaws template sections and the builder's question set.
- `election-procedures.md` — nominations, notices, eligibility, mail ballot process, observers, challenges, record preservation.
- `compliance.md` — compliance calendar items, thresholds, deadlines (config-driven, attorney/accountant review).
- `weingarten.md` — rights card.
- `fair-representation.md` — plain-language explanation for stewards of the duty to represent everyone fairly.
- `labor-management.md` — guidance on joint committees and what to share.
- `workspace-data-protection.md` — honest data-protection page for the workspace.
- `/content/training/` — steward basics, handling a grievance, investigatory interviews, running a meeting, treasurer basics, election committee basics.

---

## 11. Data ownership: export and deletion

- **Full export** (officers, passkey re-auth required): ZIP with JSON of every table scoped to the workspace, CSV versions of roster/ledger/votes/grievance metadata, PDFs of bylaws/contract/minutes, and attachments. E2E-encrypted records are exported as ciphertext plus instructions; users with keys can decrypt them in-browser into a separate export.
- **Officer handover:** a guided checklist when officers change (roles transfer, device keys for E2E records re-sealed to new officers by outgoing ones, Stripe account access updated, compliance tasks reassigned).
- **Workspace deletion:** requires approval from a majority of officers and a 14-day cooling-off period, with notices to all members. Election records under preservation are retained until their preservation period ends, then deleted.

---

## 12. Testing requirements

### Unit
- Grievance deadline calculator (calendar vs. business days, holidays, step chaining, time zones).
- Ledger balancing; reversing entries; budget vs. actuals.
- Permission matrix: every role × action × resource, auto-generated from `permissions.ts`.
- Envelope encryption round trip; E2E seal/unseal for grievance keys; vote key Shamir split and tally.
- Small-group suppression in survey and dashboard aggregates.

### Integration (API + test Postgres)
- Founding flow creates workspace, members, invitations; blocked without the "gone public" confirmation.
- **Management guest isolation:** a management guest calling every non–labor-management route receives 403, and no response body anywhere contains member data. Iterate over the full route list programmatically.
- **Ballot unlinkability:** after a vote, assert there is no column or join path linking `ballots` to `users`/`members`, ballots have no timestamps, and logs captured during voting contain no user identifiers alongside ballot requests.
- Double-voting impossible (concurrent requests in a race test).
- Dues change blocked without a passed `dues_change` vote.
- Disbursement above threshold requires two distinct approvers; self-approval rejected.
- Grievance cannot close without a decision, reason, and worker notification.
- Non-member unit employee can submit a grievance and access the contract.
- Labor–management module cannot be enabled while stage is `public_prerecognition`.
- Audit log entries created for every read of another user's personal data.
- Ledger UPDATE/DELETE rejected at the database level.
- Stripe webhook signature verification (reject unsigned/invalid).

### Plaintext-leak test (extended)
Seed a workspace with distinctive fake names, emails, phones, and addresses. Run all module flows. `pg_dump` the database and assert none of the distinctive strings appear (at-rest encryption works). Assert grievance and hardship content strings never appear in the DB or logs even in encrypted-at-rest form's decrypted server context (they're E2E).

### End-to-end (Playwright)
- Founding flow from a completed MVP campaign → claim account → join as member.
- Bylaws built, amendment proposed, voted, and ratified.
- Bargaining: proposals exchanged, all TA'd, contract assembled, ratification vote passes, contract searchable.
- Grievance: submitted by non-member, assigned, steps completed with deadlines, closed with decision.
- Dues subscription in Stripe test mode, ledger reconciliation, member financial summary shows it.
- Management guest joins safety committee, sees only that committee.

---

## 13. Build phases

Stop after each phase for my review.

**Phase V0 — Foundations.** Workspace module scaffolding, accounts (magic link + passkeys), sessions, envelope encryption, device keys, permissions matrix + middleware, audit log, workspace data-protection page, extended leak test. *Done when:* users can sign in, roles enforce access, and the permission-matrix and leak tests pass.

**Phase V1 — Founding and membership.** Founding flow from MVP unlock, CSV import, invitations, member profiles, roster, access-log view, coverage fields. *Done when:* a campaign can become a workspace end to end.

**Phase V2 — Governance and voting.** Bylaws builder, versioning, amendments with diffs, offices and term reminders, full voting system (Section 8) including unlinkable ballots, committee tally, receipts, mail-ballot officer election workflow, dues-change enforcement. *Done when:* bylaws can be ratified by secret ballot and all voting tests pass.

**Phase V3 — Meetings, communications, surveys.** *Done when:* a meeting can be scheduled, held, minuted, and published in two languages; an anonymous survey runs with suppression.

**Phase V4 — Treasury and compliance.** Stripe Connect onboarding, dues plans, webhooks, immutable ledger, disbursements with approvals, budget, member financial summary, LM data sheet export, compliance calendar. *Done when:* treasury E2E test passes in Stripe test mode.

**Phase V5 — Bargaining and contract.** Bargaining workspace, TA tracker, updates, contract assembly, ratification, contract library search, calculators, share link. *Done when:* bargaining E2E test passes.

**Phase V6 — Stewards and grievances.** Intake for all unit employees, E2E content, assignment, configurable procedure, deadline engine and reminders, informal resolution, fair-representation log, Weingarten card, coverage map, training modules. *Done when:* grievance tests pass.

**Phase V7 — Hardship fund and labor–management module.** Hardship applications (E2E) with ledger linkage; joint committees, shared issue log, early resolution threads, published metrics, "What management can see" page, management guest isolation tests. *Done when:* isolation tests pass for every route.

**Phase V8 — Union health, export, handover, polish.** Health dashboard, full export, officer handover checklist, workspace deletion with cooling-off, accessibility pass (WCAG 2.1 AA), Spanish locale scaffolding for all new strings, `docs/SECURITY_REVIEW_V2.md` walking through every V2 rule. *Done when:* all V2 tests pass and a full demo workspace runs on staging.

---

## 14. Design direction (additions to MVP Section 13)

- The workspace should feel like a **well-run community institution**: steady, clear, and fair. Same type, color, and accessibility standards as the MVP.
- Home screen for members: "What's happening" (next meeting, open votes, bargaining updates), "Get help" (file a grievance, find your steward, Weingarten card), "Your union" (bylaws, officers, finances).
- Make participation the easiest action on every screen: one tap to RSVP, vote, or answer a survey.
- Transparency is visible: "Who holds what role," "Where the money goes," and "What management can see" are linked from the main navigation, not buried.
- Deadlines and required actions use calm, unmistakable urgency (clear dates and countdowns), not alarm.
- All new UI strings in locale files.

---

## 15. Out of scope for V2

- AI features (contract Q&A, summaries, translation) that send data to third parties.
- Automatic filing of any government form or NLRB/DOL submission.
- Payroll dues checkoff integrations with employers.
- Strike logistics tools (picket scheduling, strike pay distribution) — possible V3.
- Multi-union federations or national affiliations.
- Native mobile apps.

---

## 16. New environment variables

```
WORKSPACE_MASTER_KEY=
EMAIL_LOOKUP_HMAC_KEY=
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=
STRIPE_CONNECT_CLIENT_ID=
ONLINE_OFFICER_ELECTIONS=false
SESSION_IDLE_HOURS=12
SESSION_MAX_DAYS=30
```

---

Begin with Section 0, then Phase V0. Stop and report when Phase V0 is complete.

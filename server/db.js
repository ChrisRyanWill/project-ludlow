// SQLite schema. Every text column that could hold personal data holds ciphertext (or nothing):
//  - campaign tables: ciphertext produced in the worker's browser; the server has no key.
//  - workspace tables: personal fields are *_enc (envelope-encrypted at rest); grievances are end-to-end.
// Ballots and receipts have no member reference and no timestamp, by construction.
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

export function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new Database(file);
  db.pragma('foreign_keys = ON');
  db.pragma('secure_delete = ON'); // deleted rows (a withdrawn card, a destroyed campaign) are zeroed on disk
  // Without this, INSERT OR REPLACE deletes the row it replaces WITHOUT firing the delete triggers, which would let anyone with SQL access rewrite
  // the ledger and the audit log past the "append-only" guards below.
  db.pragma('recursive_triggers = ON');
  db.exec(SCHEMA);
  // Migrations for databases created by earlier versions.
  const cardCols = db.prepare("SELECT name FROM pragma_table_info('cards')").all().map((c) => c.name);
  const campCols = db.prepare("SELECT name FROM pragma_table_info('campaigns')").all().map((c) => c.name);
  const roleCols = db.prepare("SELECT name FROM pragma_table_info('ws_roles')").all().map((c) => c.name);
  if (!roleCols.includes('removed_by_vote_id')) db.exec('ALTER TABLE ws_roles ADD COLUMN removed_by_vote_id TEXT');
  if (!campCols.includes('release_min')) db.exec('ALTER TABLE campaigns ADD COLUMN release_min INTEGER NOT NULL DEFAULT 1');
  if (!cardCols.includes('seal_mode')) db.exec("ALTER TABLE cards ADD COLUMN seal_mode TEXT NOT NULL DEFAULT 'shamir'");
  // A campaign is live as soon as its founder (trustee 1) has a key; it used to wait for every trustee.
  db.exec(`UPDATE campaigns SET status='active' WHERE status='draft' AND EXISTS
    (SELECT 1 FROM trustees t WHERE t.campaign_id=campaigns.id AND t.trustee_index=1 AND t.enrolled_at IS NOT NULL)`);
  return db;
}

export const SCHEMA = `
-- ================= Campaign system (zero-knowledge) =================
CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('draft','active','frozen')),
  threshold_k INTEGER NOT NULL, trustee_count_n INTEGER NOT NULL,
  meta_ciphertext TEXT NOT NULL, meta_nonce TEXT NOT NULL, card_template_version TEXT NOT NULL,
  release_min INTEGER NOT NULL DEFAULT 1, -- the server will not hand over the sealed cards until this many are signed and vouched
  created_at TEXT NOT NULL, last_activity_at TEXT NOT NULL,
  CHECK (threshold_k >= 2 AND threshold_k <= trustee_count_n AND trustee_count_n <= 7)
);
CREATE TABLE IF NOT EXISTS trustees (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  trustee_index INTEGER NOT NULL,
  enrollment_token_hash TEXT, box_public_key TEXT, sign_public_key TEXT, enrolled_at TEXT,
  UNIQUE (campaign_id, trustee_index)
);
CREATE TABLE IF NOT EXISTS invites (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('direct','group')),
  created_by_card_id TEXT REFERENCES cards(id) ON DELETE SET NULL,
  created_by_trustee_index INTEGER,
  max_uses INTEGER NOT NULL, use_count INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS cards (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  invite_id TEXT NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL, nonce TEXT NOT NULL, sealed_shares TEXT NOT NULL, template_version TEXT NOT NULL,
  seal_mode TEXT NOT NULL DEFAULT 'shamir', -- 'solo': sealed to the founder alone (committee not complete yet); 'shamir': k-of-n
  status TEXT NOT NULL CHECK (status IN ('pending','vouched')),
  vouch_code_hash TEXT, vouch_attempts INTEGER NOT NULL DEFAULT 0,
  member_token_hash TEXT NOT NULL UNIQUE,
  confirmation_sent_at TEXT, confirmation_message_id TEXT,
  disavow_token_hash TEXT NOT NULL, disavowed_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cards_campaign ON cards(campaign_id, status);
-- Lowering the release number needs k trustees to agree on the same value (raising it never does).
CREATE TABLE IF NOT EXISTS release_approvals (
  campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  trustee_index INTEGER NOT NULL, value INTEGER NOT NULL, approved_at TEXT NOT NULL,
  PRIMARY KEY (campaign_id, trustee_index)
);
CREATE TABLE IF NOT EXISTS destroy_approvals (
  campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  trustee_index INTEGER NOT NULL, approved_at TEXT NOT NULL,
  PRIMARY KEY (campaign_id, trustee_index)
);
-- A worker's private record of employer conduct. Encrypted with a key only their device can derive.
CREATE TABLE IF NOT EXISTS locker_entries (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  card_id TEXT NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL, nonce TEXT NOT NULL, created_at TEXT NOT NULL
);
-- A report a worker chose to share with the committee: sealed to each trustee, not linked to any card.
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL, nonce TEXT NOT NULL, sealed_keys TEXT NOT NULL, created_at TEXT NOT NULL
);

-- ================= Workspace (a union that has gone public) =================
CREATE TABLE IF NOT EXISTS ws_workspaces (
  id TEXT PRIMARY KEY,
  stage TEXT NOT NULL CHECK (stage IN ('public_prerecognition','recognized')),
  stage_note TEXT,
  union_name TEXT NOT NULL, employer_name TEXT NOT NULL, unit_description TEXT,
  jurisdiction TEXT NOT NULL DEFAULT 'us-nlra',
  timezone TEXT NOT NULL DEFAULT 'America/Denver',
  fiscal_year_start TEXT NOT NULL DEFAULT '01-01',
  policy_json TEXT NOT NULL, procedure_json TEXT NOT NULL,
  data_key_wrapped TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ws_members (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES ws_workspaces(id) ON DELETE CASCADE,
  legal_name_enc TEXT NOT NULL, email_enc TEXT, phone_enc TEXT, address_enc TEXT, job_title_enc TEXT,
  shift TEXT, location TEXT, preferred_language TEXT,
  membership_status TEXT NOT NULL DEFAULT 'unit_employee' CHECK (membership_status IN ('unit_employee','member','former')),
  founding INTEGER NOT NULL DEFAULT 0, joined_at TEXT,
  box_public_key TEXT, sign_public_key TEXT, claim_token_hash TEXT, claimed_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ws_members_ws ON ws_members(workspace_id);
CREATE TABLE IF NOT EXISTS ws_roles (
  member_id TEXT NOT NULL REFERENCES ws_members(id) ON DELETE CASCADE,
  role TEXT NOT NULL, assigned_by TEXT, assigned_at TEXT NOT NULL, removed_at TEXT, removed_by_vote_id TEXT,
  PRIMARY KEY (member_id, role)
);
CREATE TABLE IF NOT EXISTS ws_sessions (
  token_hash TEXT PRIMARY KEY,
  member_id TEXT NOT NULL REFERENCES ws_members(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL
);
-- Append-only and hash-chained: each entry commits to the one before it, so history cannot be
-- quietly rewritten, not even by whoever runs the database.
CREATE TABLE IF NOT EXISTS ws_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT NOT NULL, seq INTEGER NOT NULL,
  actor_member_id TEXT, action TEXT NOT NULL, resource_type TEXT, resource_id TEXT,
  created_at TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL,
  UNIQUE (workspace_id, seq)
);
CREATE INDEX IF NOT EXISTS ws_audit_resource ON ws_audit(workspace_id, resource_type, resource_id);
CREATE TRIGGER IF NOT EXISTS ws_audit_no_update BEFORE UPDATE ON ws_audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ws_audit_no_delete BEFORE DELETE ON ws_audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;

CREATE TABLE IF NOT EXISTS ws_announcements (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES ws_workspaces(id) ON DELETE CASCADE,
  author_member_id TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ws_bylaws_versions (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES ws_workspaces(id) ON DELETE CASCADE,
  version INTEGER NOT NULL, summary TEXT NOT NULL, policy_json TEXT NOT NULL,
  ratified_by_vote_id TEXT, created_at TEXT NOT NULL
);

-- ---- Voting: ballots carry no voter reference and no timestamp; receipts are a separate, unlinked table ----
CREATE TABLE IF NOT EXISTS ws_votes (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES ws_workspaces(id) ON DELETE CASCADE,
  title TEXT NOT NULL, description TEXT, type TEXT NOT NULL, options_json TEXT NOT NULL, pass_rule TEXT NOT NULL,
  effect_json TEXT, petition_id TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed','tallied')),
  closes_at TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, closed_at TEXT,
  vote_public_key TEXT NOT NULL, threshold_k INTEGER NOT NULL, committee_json TEXT NOT NULL,
  results_json TEXT, revealed_secret_key TEXT
);
CREATE TABLE IF NOT EXISTS ws_vote_participation (
  vote_id TEXT NOT NULL REFERENCES ws_votes(id) ON DELETE CASCADE,
  member_id TEXT NOT NULL REFERENCES ws_members(id) ON DELETE CASCADE,
  has_voted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (vote_id, member_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ws_ballots (
  id TEXT PRIMARY KEY,
  vote_id TEXT NOT NULL REFERENCES ws_votes(id) ON DELETE CASCADE,
  choice_ciphertext TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ws_vote_receipts (
  vote_id TEXT NOT NULL REFERENCES ws_votes(id) ON DELETE CASCADE,
  receipt_hash TEXT NOT NULL,
  PRIMARY KEY (vote_id, receipt_hash)
) WITHOUT ROWID;

-- ---- Member-initiated votes and recalls: enough signatures forces the committee to open a vote ----
CREATE TABLE IF NOT EXISTS ws_petitions (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES ws_workspaces(id) ON DELETE CASCADE,
  title TEXT NOT NULL, description TEXT, vote_type TEXT NOT NULL, options_json TEXT NOT NULL,
  pass_rule TEXT NOT NULL, effect_json TEXT,
  created_by TEXT NOT NULL, needed INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','qualified','opened')),
  qualified_at TEXT, vote_id TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ws_petition_signers (
  petition_id TEXT NOT NULL REFERENCES ws_petitions(id) ON DELETE CASCADE,
  member_id TEXT NOT NULL REFERENCES ws_members(id) ON DELETE CASCADE,
  PRIMARY KEY (petition_id, member_id)
);

-- ---- Grievances: content is end-to-end encrypted; the server sees only workflow metadata ----
CREATE TABLE IF NOT EXISTS ws_grievances (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES ws_workspaces(id) ON DELETE CASCADE,
  submitted_by TEXT NOT NULL REFERENCES ws_members(id), assigned_to TEXT REFERENCES ws_members(id),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
  current_step INTEGER NOT NULL DEFAULT 1, article_ref TEXT,
  content_ciphertext TEXT NOT NULL, content_nonce TEXT NOT NULL, sealed_keys TEXT NOT NULL,
  decision TEXT, reason_ciphertext TEXT, reason_nonce TEXT, worker_notified_at TEXT,
  filed_on TEXT NOT NULL, created_at TEXT NOT NULL, closed_at TEXT
);
CREATE TABLE IF NOT EXISTS ws_grievance_steps (
  grievance_id TEXT NOT NULL REFERENCES ws_grievances(id) ON DELETE CASCADE,
  step_number INTEGER NOT NULL, name TEXT NOT NULL, days INTEGER NOT NULL, day_type TEXT NOT NULL,
  started_on TEXT, due_on TEXT, completed_on TEXT, outcome TEXT,
  PRIMARY KEY (grievance_id, step_number)
);
CREATE TABLE IF NOT EXISTS ws_grievance_notes (
  id TEXT PRIMARY KEY, grievance_id TEXT NOT NULL REFERENCES ws_grievances(id) ON DELETE CASCADE,
  author_member_id TEXT NOT NULL, ciphertext TEXT NOT NULL, nonce TEXT NOT NULL, created_at TEXT NOT NULL
);

-- ---- Money: immutable, hash-chained ledger; corrections are new reversing entries ----
CREATE TABLE IF NOT EXISTS ws_ledger (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES ws_workspaces(id),
  seq INTEGER NOT NULL, entry_date TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('receipt','disbursement')),
  amount_cents INTEGER NOT NULL CHECK (amount_cents > 0), category TEXT NOT NULL,
  payee_enc TEXT, memo_enc TEXT, commit_hash TEXT NOT NULL,
  disbursement_id TEXT, reverses_id TEXT UNIQUE,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL,
  UNIQUE (workspace_id, seq)
);
CREATE TRIGGER IF NOT EXISTS ws_ledger_no_update BEFORE UPDATE ON ws_ledger BEGIN SELECT RAISE(ABORT, 'ledger entries are immutable'); END;
CREATE TRIGGER IF NOT EXISTS ws_ledger_no_delete BEFORE DELETE ON ws_ledger BEGIN SELECT RAISE(ABORT, 'ledger entries are immutable'); END;
CREATE TABLE IF NOT EXISTS ws_disbursements (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES ws_workspaces(id) ON DELETE CASCADE,
  requested_by TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK (amount_cents > 0), category TEXT NOT NULL,
  payee_enc TEXT, memo_enc TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','paid')),
  required_approvals INTEGER NOT NULL, paid_ledger_id TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ws_disbursement_approvals (
  disbursement_id TEXT NOT NULL REFERENCES ws_disbursements(id) ON DELETE CASCADE,
  approver_id TEXT NOT NULL, decision TEXT NOT NULL CHECK (decision IN ('approve','reject')), created_at TEXT NOT NULL,
  PRIMARY KEY (disbursement_id, approver_id)
);
CREATE TABLE IF NOT EXISTS ws_dues_plans (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES ws_workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0),
  approved_by_vote_id TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ws_compliance (
  workspace_id TEXT NOT NULL REFERENCES ws_workspaces(id) ON DELETE CASCADE,
  task_key TEXT NOT NULL, done_at TEXT, PRIMARY KEY (workspace_id, task_key)
);
`;

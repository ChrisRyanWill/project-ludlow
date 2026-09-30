// The single source of truth for who may do what in the workspace (V2 rule 15).
// Every workspace route declares exactly one action from this table; the test suite walks the
// route table and checks every role against it. '*' means any signed-in unit employee.
// Representation is never gated by dues (V2 rule 7): filing a concern, the procedure and the
// Weingarten card are '*' — no membership required.
export const ROLES = ['unit_employee', 'member', 'steward', 'chief_steward', 'officer', 'treasurer', 'election_committee'];
export const ASSIGNABLE_ROLES = ['officer', 'treasurer', 'chief_steward', 'steward', 'election_committee'];

export const PERMS = {
  'ws.read': ['*'],
  'ws.stage.set': ['officer'],
  'me.write': ['*'],
  'roles.read': ['*'],
  'roles.assign': ['officer'],
  'roster.read': ['officer', 'treasurer', 'chief_steward'],
  'roster.add': ['officer'],
  'keyring.read': ['*'],
  'audit.read_all': ['officer'],
  'export.all': ['officer'],
  'announce.read': ['*'],
  'announce.write': ['officer'],
  'health.read': ['officer', 'treasurer', 'chief_steward'],
  'compliance.read': ['officer', 'treasurer'],
  'compliance.write': ['officer', 'treasurer'],
  'vote.read': ['*'],
  'petition.create': ['member'],
  'petition.sign': ['member'],
  'vote.create': ['officer', 'election_committee'],
  'vote.cast': ['member'],
  'vote.close': ['officer', 'election_committee'],
  'vote.tally': ['*'], // who counts a vote is fixed when it opens: the routes check the vote's own committee, so removing the role afterwards cannot stop the count
  'grievance.submit': ['*'],
  'grievance.list': ['*'],
  'grievance.share': ['*'], // only someone holding the case key can hand it on; the route checks that
  'grievance.assign': ['chief_steward'],
  'grievance.work': ['steward', 'chief_steward'],
  'procedure.read': ['*'],
  'procedure.write': ['officer', 'chief_steward'],
  'finance.read': ['member', 'officer', 'treasurer'],
  'ledger.record': ['treasurer'],
  'ledger.reverse': ['treasurer'],
  'disbursement.request': ['officer', 'treasurer'],
  'disbursement.approve': ['officer', 'treasurer'],
  'disbursement.pay': ['treasurer'],
  'dues.set': ['officer', 'treasurer'],
};

export const can = (roles, action) => {
  const allowed = PERMS[action];
  if (!allowed) return false; // unknown action: fail closed
  return allowed.includes('*') || allowed.some((r) => roles.has ? roles.has(r) : roles.includes(r));
};

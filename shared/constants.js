export const APP_NAME = 'Project Ludlow';
export const CARD_TEMPLATE_VERSION = 'card-v1';
export const THRESHOLDS = { petition: 0.3, majority: 0.5, supermajority: 0.7 };
export const STAGES = ['public_prerecognition', 'recognized'];
export const VOTE_TYPES = ['general', 'bylaws_amendment', 'ratification', 'dues_change', 'strike_authorization', 'officer_election', 'recall'];

// Bylaws as data: these numbers are enforced by the software, and can only change by a passed
// bylaws_amendment vote. "Democratic defaults": members can force a vote and recall officers.
export const POLICY_FIELDS = {
  petitionPct: { label: 'Members needed to force a vote (percent of members)', min: 1, max: 50, def: 10 },
  recallPct: { label: 'Members needed to force a recall vote (percent of members)', min: 1, max: 50, def: 15 },
  twoApprovalCents: { label: 'Spending at or above this needs two officers to approve (cents)', min: 0, max: 100_000_000, def: 50_000 },
  termMonths: { label: 'Officer term length (months)', min: 6, max: 36, def: 24 },
};
export const DEFAULT_POLICY = Object.fromEntries(Object.entries(POLICY_FIELDS).map(([k, v]) => [k, v.def]));
// Votes where an employer or a faction could pressure members to prove how they voted. Once the ballot key is published, anyone who kept a copy of
// their own encrypted ballot can prove it, so the counting page does not start with publishing ticked for these (docs/research/ballot-secrecy.md).
export const COERCION_RISK_TYPES = ['strike_authorization', 'ratification'];
// A decision with an effect (dues, rules, removal) is always published so anyone can recount it.
export const publishByDefault = ({ type, hasEffect }) => !!hasEffect || !COERCION_RISK_TYPES.includes(type);
export const PASS_RULES = ['majority', 'two_thirds', 'plurality'];
export const GRIEVANCE_DECISIONS = ['pursue', 'resolved_informally', 'not_pursued'];
// A grievance's contract reference is stored in the clear, so it must stay a reference, never a narrative:
// short, and only the characters article numbers use ("Art. 12", "§ 4", "Art. 5(b)", "12/3", "Art. 7, 9").
export const ARTICLE_REF = /^[A-Za-z0-9 .,§()\/-]{1,20}$/;
export const SMALL_GROUP = 5; // breakdowns with fewer people than this are hidden

// TODO(accountant): align these with the Department of Labor LM-2/LM-3 line items before real use.
export const RECEIPT_CATEGORIES = {
  dues: 'Dues', fees: 'Fees and assessments', donations: 'Donations and grants',
  interest: 'Interest and investments', other_receipt: 'Other receipts',
};
export const DISBURSEMENT_CATEGORIES = {
  representation: 'Representation and bargaining', member_benefits: 'Member benefits and hardship aid',
  education: 'Education and training', office: 'Office and administration',
  professional: 'Professional fees (legal, accounting)', political: 'Political activities and lobbying',
  affiliation: 'Affiliation and per-capita dues', other_disbursement: 'Other disbursements',
};
// Payees in these categories are shown to members as "Member" so aid recipients stay private.
export const REDACTED_CATEGORIES = ['member_benefits'];

export const DEFAULT_PROCEDURE = {
  steps: [
    { name: 'Step 1: Supervisor', days: 5, dayType: 'business' },
    { name: 'Step 2: Manager', days: 10, dayType: 'business' },
    { name: 'Step 3: Demand for arbitration', days: 30, dayType: 'calendar' },
  ],
  holidays: [],
};

// Pass rules. "majority" and "two_thirds" look at option 0 (put "Yes" first); "plurality" picks a unique winner.
export function evaluateVote(counts, rule) {
  const total = counts.reduce((a, b) => a + b, 0);
  if (rule === 'plurality') {
    const max = Math.max(...counts);
    const winners = counts.flatMap((c, i) => (c === max ? [i] : []));
    return { total, passed: total > 0 && winners.length === 1, winner: total > 0 && winners.length === 1 ? winners[0] : null };
  }
  const yes = counts[0] || 0;
  const passed = total > 0 && (rule === 'two_thirds' ? yes * 3 >= total * 2 : yes * 2 > total);
  return { total, passed, winner: null };
}

export const isoDay = (d) => d.toISOString().slice(0, 10);

// Suggested compliance calendar. Every date and threshold here is a starting point, not legal advice.
// TODO(lawyer): confirm each item and deadline. TODO(accountant): confirm the LM form thresholds.
export function complianceTasks({ createdOn, fiscalYearStart = '01-01', today, receiptsCents = 0 }) {
  const add = (iso, n) => { const d = new Date(iso + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return isoDay(d); };
  const [fm, fd] = fiscalYearStart.split('-').map(Number);
  const y = Number(today.slice(0, 4));
  let start = new Date(Date.UTC(y, fm - 1, fd));
  if (isoDay(start) > today) start = new Date(Date.UTC(y - 1, fm - 1, fd));
  const fyEnd = new Date(Date.UTC(start.getUTCFullYear() + 1, fm - 1, fd - 1));
  const form = receiptsCents < 1_000_000 ? 'LM-4' : receiptsCents < 25_000_000 ? 'LM-3' : 'LM-2';
  const irsDue = new Date(Date.UTC(fyEnd.getUTCFullYear(), fyEnd.getUTCMonth() + 5, 15));
  return [
    { key: 'lm1', title: 'File the initial union registration (Form LM-1) with your constitution and bylaws', dueOn: add(createdOn, 90), owner: 'officer', verify: 'lawyer',
      detail: 'Due within 90 days of becoming subject to the LMRDA. A human files it; Project Ludlow never files anything for you.' },
    { key: 'annual_report', title: `File the annual financial report (${form}) for the year ending ${isoDay(fyEnd)}`, dueOn: add(isoDay(fyEnd), 90), owner: 'treasurer', verify: 'accountant',
      detail: `Due 90 days after fiscal year end. The form depends on annual receipts (this year so far: about $${Math.round(receiptsCents / 100).toLocaleString('en-US')}).` },
    { key: 'irs', title: 'File the annual IRS return for a tax-exempt organization (990 series)', dueOn: isoDay(irsDue), owner: 'treasurer', verify: 'accountant',
      detail: 'Usually due on the 15th day of the 5th month after the year ends. Also confirm your tax-exempt status application is done.' },
    { key: 'bond', title: 'Make sure everyone who handles union money is covered by a fidelity bond', dueOn: null, owner: 'treasurer', verify: 'lawyer',
      detail: 'Required before anyone handles funds. The amount is based on the prior year\'s funds handled; confirm the rules for your size.' },
    { key: 'election', title: 'Hold the first officer election under your bylaws', dueOn: add(createdOn, 365), owner: 'officer', verify: 'lawyer',
      detail: 'Suggested within a year. Local union officers must be elected at least every three years. Keep every election record for one year afterward.' },
  ];
}

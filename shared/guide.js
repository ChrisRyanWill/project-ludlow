// "What to do next." Given where a person is, return the ONE next step (or null when there is nothing to do), so the app can show a single quiet
// card instead of a manual. Steps are data: a stable id (so a person can hide one), an English title and reason (translated by the page, keyed by
// these exact sentences), and either a `target` on the same page (the element to scroll to and highlight) or an `href`. Nothing here files or sends
// anything: steps that end with the employer or an agency lead to drafts a person reviews and sends themselves (CLAUDE.md rule 14).

// A trustee's dashboard. s: { status, isFounder, n, joined, confirmed, solo, pending, vouched, releaseMin, k }
export function organizeStep(s) {
  if (s.status === 'frozen') return { id: 'frozen', title: 'Signing is paused.', why: 'Resume it under Safety controls when it is safe to continue.', target: 'g-safety' };
  if (s.joined < s.n) {
    return s.isFounder
      ? { id: 'invite-trustees', title: 'Invite your other trustees.', why: 'Until every trustee has joined and you confirm the committee, only you can open the cards.', target: 'g-committee', vars: {} }
      : { id: 'wait-trustees', title: 'Read your key words to trustee 1.', why: 'Trustee 1 checks them before confirming the committee, so nobody can slip in a different key.', target: 'g-committee' };
  }
  if (!s.confirmed) {
    return s.isFounder
      ? { id: 'confirm-committee', title: 'Check each trustee\'s key words, then confirm the committee.', why: 'Do it by phone or in person. After that, cards are locked so that any {k} of you are needed.', target: 'g-committee', vars: { k: s.k } }
      : { id: 'wait-confirm', title: 'Read your key words to trustee 1.', why: 'Trustee 1 checks them before confirming the committee, so nobody can slip in a different key.', target: 'g-committee' };
  }
  if (s.solo > 0 && s.isFounder) return { id: 'lock-early', title: 'Lock the early cards to the committee.', why: '{n} early card(s) are still sealed to you alone.', target: 'g-committee', vars: { n: s.solo } };
  if (s.pending > 0) return { id: 'confirm-pending', title: '{n} person(s) are waiting to be confirmed.', why: 'Enter their two-word code only after you have confirmed them in person.', target: 'g-pending', vars: { n: s.pending } };
  if (s.vouched < s.releaseMin) return { id: 'invite-coworkers', title: 'Invite coworkers you trust to sign.', why: '{m} more signed card(s) are needed before the cards can be opened.', target: 'g-invite', vars: { m: s.releaseMin - s.vouched } };
  return { id: 'open-cards', title: 'Enough people have signed.', why: 'When you decide together to go public, {k} trustees meet and open the cards. You get drafts to review and send yourselves; nothing is sent for you.', target: 'g-open', vars: { k: s.k } };
}

// A member's workspace home. s: { isMember, voteNow: {id,title}|null, overdueCase: {id}|null, dueTask: {title}|null, recognized }
// Only things that need this person now; nothing at all when there is nothing to do.
export function workspaceStep(s) {
  if (s.voteNow) return { id: 'vote-' + s.voteNow.id, title: 'A vote is open for you: {title}', why: 'Your ballot is secret. It takes a minute.', href: `/w/votes/${s.voteNow.id}`, vars: { title: s.voteNow.title } };
  if (s.overdueCase) return { id: 'case-' + s.overdueCase.id, title: 'A case you are working on is overdue.', why: 'A missed step can cost the worker their case. Open it to see what is due.', href: `/w/help/${s.overdueCase.id}` };
  if (s.dueTask) return { id: 'task-' + s.dueTask.key, title: 'Coming up: {title}', why: 'The compliance calendar on the Union page has the details. It is a reminder, not legal advice.', href: '/w/union', vars: { title: s.dueTask.title } };
  if (!s.isMember) return { id: 'join', title: 'Join the union to vote and see the books.', why: 'Getting help never depends on joining.', target: 'g-join' };
  return null;
}

import { div, h1, h2, h3, p, a, ul, li, strong, span, button, input, md, shell, setTitle, linkBtn, callout, field, btn, toast, readAloud, view, badge } from './ui.js';
import { t } from './i18n.js';
import { PACKS } from './packs.js';
import { sha256HexBytes, ready } from '../../shared/crypto.js';
import safetyMd from '../../content/legal/common/safety.md';
import protectedMd from '../../content/legal/common/data-protection.md';
import termsMd from '../../content/legal/common/terms.md';

export function HomePage() {
  setTitle('Start a union safely');
  return shell(div({ class: 'wrap' },
    div({ class: 'hero' },
      h1(t('Start a union at your workplace, safely.')),
      p({ class: 'lead' }, t('Collect signed authorization cards that only your own committee can ever read. Then run your union openly and fairly, with tools that let every member check the work.')),
      div({ class: 'row' }, linkBtn(t('Start a campaign'), '/start', 'primary'), linkBtn(t('Open my union workspace'), '/w', 'secondary')),
      p({ class: 'small muted' }, t('Got an invitation link from a coworker? Just open it. You do not need an account.'))),
    div({ class: 'card' },
      h2(t('How it works')),
      ul({ class: 'steps' },
        li(strong(t('A few trusted coworkers become trustees.')), ' ', t('You can start alone and add them as you go. Once your committee is complete, any group of them, for example 3 of 5, can open the cards, and only after enough people have signed. No one alone can.')),
        li(strong(t('Coworkers sign on their own phones.')), ' ', t('Each card is locked on the phone before it is sent. This website only ever sees scrambled data.')),
        li(strong(t('You decide when to go public.')), ' ', t('When you have enough support, the trustees open the cards together and get a package to review: a roster, the cards, and draft letters and forms.')),
        li(strong(t('Then run the union in the open.')), ' ', t('Votes, money and workplace cases, built so that every member can check that they were done fairly.')))),
    div({ class: 'card' },
      h2(t('Built so you do not have to trust us')),
      ul(
        li(t('Cards are encrypted in the browser. Not even this website can read them.')),
        li(t('Votes are secret, and after a vote every member can recount the ballots themselves.')),
        li(t('The union\'s books are a chain that cannot be quietly edited. Your browser checks it.')),
        li(t('Spending needs two officers. Members can force a vote or a recall by petition.')),
        li(t('You can run your own copy of the server and export everything at any time.')))),
    callout('info', strong(t('This is a tool.')), ' ', t('It is not a union and not a law firm. It never files anything or contacts your employer for you. Everything it produces is a draft for people to review.'))));
}

export const SafetyPage = () => { setTitle('Safety tips'); return shell(div({ class: 'wrap' }, md(safetyMd))); };
export const ProtectedPage = () => { setTitle('How your data is protected'); return shell(div({ class: 'wrap' }, md(protectedMd))); };
export const TermsPage = () => { setTitle('Terms'); return shell(div({ class: 'wrap' }, md(termsMd))); };

export function RightsPage() {
  setTitle('Your rights');
  let cur = 'us-nlra';
  return shell(div({ class: 'wrap' }, view((update) => div(
    h1(t('Your rights')),
    div({ class: 'row tabs-inline' }, Object.values(PACKS).map((k) => button({ class: `btn small ${cur === k.id ? 'primary' : 'secondary'}`, type: 'button', onclick: () => { cur = k.id; update(); }, 'aria-pressed': cur === k.id }, k.name))),
    md(PACKS[cur].rights),
    readAloud(PACKS[cur].rights.replace(/[>#*`]/g, ''))))));
}

// A page that lets anyone check the code they are running against a published fingerprint.
export function VerifyPage() {
  setTitle('Verify this software');
  const out = div({ class: 'muted' }, t('Working...'));
  const known = input({ type: 'text', placeholder: t('Paste the published fingerprint here'), autocomplete: 'off', spellcheck: false });
  let mine = '';
  const compare = () => {
    const v = known.value.trim().toLowerCase();
    if (!v) return toast(t('Paste a fingerprint first.'), 'bad');
    toast(v === mine ? t('Match: this is the software that was published.') : t('They do NOT match. Do not enter any private information.'), v === mine ? '' : 'bad');
  };
  (async () => {
    await ready;
    try {
      const bytes = new Uint8Array(await (await fetch('/app.js', { cache: 'no-store' })).arrayBuffer());
      mine = sha256HexBytes(bytes);
      const info = await (await fetch('/build.json', { cache: 'no-store' })).json().catch(() => ({}));
      out.replaceChildren(
        p(t('The code running in your browser has this SHA-256 fingerprint:')), div({ class: 'link-box' }, mine),
        p({ class: 'small muted' }, t('Version {v}', { v: info.version || '?' })));
    } catch { out.replaceChildren(t('Could not read the software to check it.')); }
  })();
  return shell(div({ class: 'wrap' },
    h1(t('Verify this software')),
    p(t('The biggest risk in any web app is a server that quietly sends you different code. You can protect yourself by comparing the fingerprint of the code you are running with the one published for the release, and by comparing with your fellow trustees before you open cards.')),
    div({ class: 'card' }, out, field(t('Published fingerprint'), known), btn(t('Compare'), compare, { kind: 'primary' })),
    callout('warn', t('Honest limits: this check cannot catch a server that shows different code to different visitors. That is why trustees should also compare the fingerprint with each other, and why you can run your own copy of the server.'))));
}

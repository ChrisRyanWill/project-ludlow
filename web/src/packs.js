// Jurisdiction packs: everything that depends on the law where you work is DATA here (thresholds,
// card wording, document templates, primers), not code. To support another country, add a pack and
// its markdown files. Every text carries a "requires review by a licensed labor attorney" header.
import usCard from '../../content/legal/us-nlra/card-v1.md';
import usCardEs from '../../content/legal/us-nlra/card-v1.es.md';
import usDecl from '../../content/legal/us-nlra/declaration.md';
import usDemand from '../../content/legal/us-nlra/recognition-demand-letter.md';
import usNext from '../../content/legal/us-nlra/next-steps.md';
import usRights from '../../content/legal/us-nlra/rights.md';
import usForm from '../../content/legal/us-nlra/form-502-worksheet.md';
import usUlp from '../../content/legal/us-nlra/ulp-worksheet.md';
import usWein from '../../content/legal/us-nlra/weingarten.md';
import ukCard from '../../content/legal/uk-cac/card-v1.md';
import ukNext from '../../content/legal/uk-cac/next-steps.md';
import ukRights from '../../content/legal/uk-cac/rights.md';
import ukLetter from '../../content/legal/uk-cac/recognition-request-letter.md';
import gCard from '../../content/legal/generic/card-v1.md';
import gNext from '../../content/legal/generic/next-steps.md';
import gRights from '../../content/legal/generic/rights.md';
import gLetter from '../../content/legal/generic/recognition-request-letter.md';

export const PACKS = {
  'us-nlra': {
    id: 'us-nlra', name: 'United States: private sector (NLRA)', currency: 'USD', ulpMonths: 6,
    blurb: 'Most private-sector workers. Elections are run by the National Labor Relations Board.',
    markers: [
      { pct: 0.3, label: '30%: enough to ask the NLRB for an election' },
      { pct: 0.5, label: '50% + 1: a majority' },
      { pct: 0.7, label: '70%: a safe cushion before you go public' },
    ],
    cards: { en: usCard, es: usCardEs },
    docs: { declaration: usDecl, letter: usDemand, letterName: 'recognition-demand-letter', next: usNext, form: usForm, ulp: usUlp },
    rights: usRights, weingarten: usWein,
  },
  'uk-cac': {
    id: 'uk-cac', name: 'United Kingdom: statutory recognition (CAC)', currency: 'GBP', ulpMonths: null,
    blurb: 'Recognition through the Central Arbitration Committee. Rules changed in April 2026.',
    markers: [
      { pct: 0.1, label: '10%: the minimum membership to apply to the CAC (this may be lowered)' },
      { pct: 0.5, label: '50% + 1: more than half; the CAC can usually recognise without a ballot' },
      { pct: 0.7, label: '70%: a safe cushion before you go public' },
    ],
    cards: { en: ukCard },
    docs: { letter: ukLetter, letterName: 'recognition-request-letter', next: ukNext },
    rights: ukRights, weingarten: null,
  },
  generic: {
    id: 'generic', name: 'Somewhere else (general guidance)', currency: 'USD', ulpMonths: null,
    blurb: 'Project Ludlow does not know your local law. You will add your own recognition threshold.',
    markers: [
      { pct: 0.5, label: '50% + 1: a majority' },
      { pct: 0.7, label: '70%: a safe cushion before you go public' },
    ],
    cards: { en: gCard },
    docs: { letter: gLetter, letterName: 'recognition-request-letter', next: gNext },
    rights: gRights, weingarten: null,
  },
};
export const packOf = (id) => PACKS[id] || PACKS.generic;

// The progress-bar markers for a campaign. In the generic pack the trustees may add their own legal threshold.
export function markersFor(pack, meta) {
  const own = Number(meta?.legalThresholdPct);
  const list = [...pack.markers];
  if (pack.id === 'generic' && own > 0 && own < 100) list.unshift({ pct: own / 100, label: `${own}%: the threshold in your local law` });
  return list.sort((a, b) => a.pct - b.pct);
}

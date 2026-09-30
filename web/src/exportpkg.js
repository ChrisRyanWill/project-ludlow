// Builds the filing package entirely in the browser from cards the trustees have just decrypted.
// Nothing here is ever sent to the server. Every generated document is a DRAFT for humans to review.
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import { zip, toCsv } from './zip.js';
import { fill, cardBody } from './ui.js';
import { cardTextMatches } from '../../shared/verify.js';

export const DRAFT_FOOTER = 'DRAFT: review with a labor attorney before filing or sending.';
const enc = new TextEncoder();
const bytes = (s) => enc.encode(s);
const digits = (s) => String(s || '').replace(/\D/g, '');

// ---------- PDF ----------
async function newPdf() {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica), bold = await doc.embedFont(StandardFonts.HelveticaBold);
  const ok = new Map();
  // Standard PDF fonts cannot draw every script; unsupported characters become "?" instead of crashing.
  const safe = (s) => [...String(s ?? '').replace(/\t/g, '  ').replace(/[\u0000-\u0009\u000b-\u001f]/g, '')].map((ch) => {
    if (ch === '\n') return ch;
    if (!ok.has(ch)) { try { font.encodeText(ch); ok.set(ch, true); } catch { ok.set(ch, false); } }
    return ok.get(ch) ? ch : '?';
  }).join('');
  const W = 612, H = 792, M = 56;
  const wrap = (text, f, size, maxW) => {
    const out = [];
    for (const para of safe(text).split('\n')) {
      let line = '';
      for (const word of para.split(' ')) {
        const tryLine = line ? line + ' ' + word : word;
        if (f.widthOfTextAtSize(tryLine, size) > maxW && line) { out.push(line); line = word; } else line = tryLine;
      }
      out.push(line);
    }
    return out;
  };
  const footer = (page) => page.drawText(DRAFT_FOOTER, { x: M, y: 30, size: 8, font, color: rgb(0.4, 0.4, 0.4) });
  return { doc, font, bold, W, H, M, wrap, safe, footer };
}

// Plain text (with a little markdown) to a paginated PDF.
export async function textPdf(title, markdown) {
  const P = await newPdf();
  let page = P.doc.addPage([P.W, P.H]), y = P.H - P.M;
  const line = (text, f, size, gap = 4) => {
    for (const l of P.wrap(text, f, size, P.W - 2 * P.M)) {
      if (y < P.M + 20) { P.footer(page); page = P.doc.addPage([P.W, P.H]); y = P.H - P.M; }
      page.drawText(l, { x: P.M, y, size, font: f });
      y -= size + gap;
    }
  };
  line(title, P.bold, 15, 8);
  for (const raw of markdown.split('\n')) {
    const s = raw.replace(/^>\s?/, '').replace(/\*\*|`/g, '').replace(/\*/g, '');
    if (/^#{1,4}\s/.test(s)) { y -= 6; line(s.replace(/^#+\s/, ''), P.bold, 12); }
    else if (!s.trim()) y -= 6;
    else line(/^\s*[-\d]/.test(s) ? s : s, P.font, 10.5);
  }
  P.footer(page);
  return P.doc.save();
}

const FIELD_ROWS = (c) => [
  ['Name', c.payload.legalName], ['Email', c.payload.personalEmail], ['Phone', c.payload.phone],
  ['Job title', c.payload.jobTitle], ['Shift or department', c.payload.shiftOrDepartment], ['Preferred language', c.payload.preferredLanguage],
];
export async function cardsPdf(cards, meta) {
  const P = await newPdf();
  cards.forEach((c, i) => {
    const page = P.doc.addPage([P.W, P.H]);
    let y = P.H - P.M;
    page.drawText(P.safe(`${meta.unionName}: authorization card #${i + 1}`), { x: P.M, y, size: 15, font: P.bold }); y -= 28;
    const body = P.wrap(c.payload.cardText, P.font, 11, P.W - 2 * P.M - 24);
    const boxH = body.length * 15 + 24;
    page.drawRectangle({ x: P.M, y: y - boxH + 8, width: P.W - 2 * P.M, height: boxH, borderColor: rgb(0.12, 0.3, 0.23), borderWidth: 1.5 });
    let by = y - 12;
    for (const l of body) { page.drawText(l, { x: P.M + 12, y: by, size: 11, font: P.font }); by -= 15; }
    y -= boxH + 20;
    for (const [k, v] of FIELD_ROWS(c)) if (v) { page.drawText(P.safe(`${k}: ${v}`), { x: P.M, y, size: 11, font: P.font }); y -= 16; }
    y -= 8;
    page.drawText(P.safe(`Typed signature: ${c.payload.typedSignature}`), { x: P.M, y, size: 13, font: P.bold }); y -= 22;
    const facts = [
      ['Date signed (server clock, UTC)', c.createdAt], ['Card version', c.templateVersion], ['Card text SHA-256', `${c.payload.cardTextSha256}${cardTextMatches(c.payload) ? ' (matches the text above)' : ' (DOES NOT MATCH the text above: check this card)'}`],
      ['Confirmation email sent (UTC)', c.confirmationSentAt || 'not sent'], ['Disavowed by signer', c.disavowedAt || 'no'],
    ];
    for (const [k, v] of facts) { for (const l of P.wrap(`${k}: ${v}`, P.font, 9, P.W - 2 * P.M)) { page.drawText(l, { x: P.M, y, size: 9, font: P.font }); y -= 12; } }
    P.footer(page);
  });
  return P.doc.save();
}

// ---------- roster ----------
export function buildRoster(cards, meta) {
  const count = (key) => cards.reduce((m, c) => m.set(key(c), (m.get(key(c)) || 0) + 1), new Map());
  const emails = count((c) => (c.payload.personalEmail || '').trim().toLowerCase());
  const phones = count((c) => digits(c.payload.phone));
  return cards.map((c, i) => {
    const flags = [];
    if (emails.get((c.payload.personalEmail || '').trim().toLowerCase()) > 1) flags.push('duplicate email');
    if (phones.get(digits(c.payload.phone)) > 1) flags.push('duplicate phone');
    if (!c.confirmationSentAt) flags.push('no confirmation sent');
    if (c.disavowedAt) flags.push('DISAVOWED by signer');
    if (!cardTextMatches(c.payload)) flags.push('CARD TEXT DOES NOT MATCH ITS FINGERPRINT');
    return { n: i + 1, card: c, flags };
  });
}

export async function buildPackage({ meta, pack, cards, includeDisavowed, appName = 'Project Ludlow', lang = 'en', unitSize }) {
  const sorted = [...cards].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  const disavowed = sorted.filter((c) => c.disavowedAt);
  const use = includeDisavowed ? sorted : sorted.filter((c) => !c.disavowedAt);
  const roster = buildRoster(use, meta);
  const today = new Date().toISOString().slice(0, 10);
  const size = unitSize || meta.estimatedUnitSize || 0;
  const majority = size > 0 && use.length * 2 > size;
  const vars = {
    employerName: meta.employerName, unionName: meta.unionName, employerAddress: meta.employerAddress || '[employer address]', unitDescription: meta.unitDescription,
    unitSize: String(size), cardCount: String(use.length), disavowedCount: String(disavowed.length), percent: size ? Math.round((use.length / size) * 100) + '%' : '?',
    templateVersions: [...new Set(use.map((c) => c.templateVersion))].join(', '), appName, date: today,
    responseDate: new Date(Date.now() + 14 * 86400_000).toISOString().slice(0, 10),
    // Never let the software help someone tell an employer they have a majority when they do not.
    majorityClaim: majority ? 'A majority of the employees in the following group' : '[NOT YET A MAJORITY: do not send this letter as written] Some of the employees in the following group',
    incidents: '(Add the incidents from your private record here.)',
  };
  const files = [];
  const add = (name, data) => files.push({ name, data: typeof data === 'string' ? bytes(data) : data });
  const doc = async (base, title, mdText) => { const text = fill(mdText, vars); add(`${base}-DRAFT.md`, text); add(`${base}-DRAFT.pdf`, await textPdf(title, text)); };

  add('roster.csv', toCsv([
    ['#', 'Legal name', 'Email', 'Phone', 'Employer', 'Union', 'Date signed (UTC, server clock)', 'Job title', 'Shift or department', 'Preferred language', 'Confirmation sent (UTC)', 'Disavowed', 'Flags for human review'],
    ...roster.map(({ n, card: c, flags }) => [n, c.payload.legalName, c.payload.personalEmail, c.payload.phone, c.payload.employerName, c.payload.unionName, c.createdAt, c.payload.jobTitle, c.payload.shiftOrDepartment, c.payload.preferredLanguage, c.confirmationSentAt || '', c.disavowedAt ? 'yes' : 'no', flags.join('; ')]),
  ]));
  add('confirmations-log.csv', toCsv([['#', 'Confirmation sent (UTC)', 'Provider message id', 'Disavowed (UTC)'], ...roster.map(({ n, card: c }) => [n, c.confirmationSentAt || '', c.confirmationMessageId || '', c.disavowedAt || ''])]));
  add('cards.pdf', await cardsPdf(use, meta));
  if (pack.docs.declaration) await doc('declaration', 'Declaration regarding electronic signatures', pack.docs.declaration);
  await doc(pack.docs.letterName, 'Request for recognition', pack.docs.letter);
  if (pack.docs.form) await doc('form-502-worksheet', 'NLRB petition worksheet', pack.docs.form);
  add('NEXT-STEPS.md', fill(pack.docs.next, vars));
  add('README.txt', [
    `${appName} filing package for ${meta.unionName}`, `Created ${today} in your browser. Nothing here was sent to any server.`, '',
    `Cards included: ${use.length} (${disavowed.length} disavowed ${includeDisavowed ? 'and included for review' : 'and excluded'}).`, '',
    'Every document is a DRAFT. Have a labor attorney or experienced organizer review it before you file or send anything.',
    'This folder contains real names and contact details. Keep it private: store it encrypted, share it only with the committee.', '',
    'roster.csv, cards.pdf, confirmations-log.csv, the declaration and the letters are described in NEXT-STEPS.md.',
  ].join('\n'));
  const slug = meta.unionName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'union';
  return { name: `${slug}-cards-${today}.zip`, bytes: zip(files), fileNames: files.map((f) => f.name), roster, majority };
}

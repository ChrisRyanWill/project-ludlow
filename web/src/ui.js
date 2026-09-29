// DOM helpers. There is NO innerHTML anywhere in this app: everything is built with createElement and
// textContent, so a hostile name or note can never become markup. (A test greps the source for it.)
import { t, getLang } from './i18n.js';
import { store } from './store.js';
import { friendly } from './api.js';
import { formatDate, formatDateTime, formatMoney } from './format.js';

export function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k === 'style') Object.assign(e.style, v); // CSSOM, allowed by our strict CSP
      else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k in e && k !== 'list' && k !== 'form') e[k] = v;
      else e.setAttribute(k, v === true ? '' : v);
    }
  }
  append(e, kids);
  return e;
}
function append(e, kids) {
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}
// Replace an element's children, flattening arrays and skipping null/false (replaceChildren alone would print them).
export function setKids(e, ...kids) { e.replaceChildren(); append(e, kids); return e; }
const isProps = (a) => a && typeof a === 'object' && !(a instanceof Node) && !Array.isArray(a);
export const el = new Proxy({}, { get: (_, tag) => (a, ...rest) => (isProps(a) ? h(tag, a, ...rest) : h(tag, null, a, ...rest)) });
export const { div, span, p, a, img, ul, ol, li, h1, h2, h3, h4, strong, em, small, pre, code, hr, section, header, nav, footer, table, thead, tbody, tr, td, th, label, form, input, textarea, button, select, option, details, summary, blockquote, mark } = el;

// ---------- svg ----------
export function svg(tag, attrs, ...kids) {
  const e = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  for (const c of kids) if (c) e.append(c);
  return e;
}

// ---------- small components ----------
export const btn = (text, onclick, { kind = '', disabled = false, type = 'button', cls = '' } = {}) =>
  button({ class: `btn ${kind} ${cls}`.trim(), type, onclick, disabled }, text);
export const callout = (kind, ...kids) => div({ class: `callout ${kind}`, role: kind === 'danger' ? 'alert' : undefined }, ...kids);
export const badge = (text, kind = '') => span({ class: `badge ${kind}` }, text);
export const field = (labelText, control, hint) => label({ class: 'field' }, span({ class: 'lbl' }, labelText), control, hint ? span({ class: 'hint' }, hint) : null);
export const textInput = (props = {}) => input({ type: 'text', autocomplete: 'off', ...props });
export function selectBox(options, current, onchange, props = {}) {
  return select({ onchange: (e) => onchange(e.target.value), ...props }, options.map(([v, l]) => option({ value: v, selected: v === current }, l)));
}
export const linkBtn = (text, href, kind = '') => a({ class: `btn ${kind}`.trim(), href }, text);

// ---------- formatting ----------
export const fmtDate = (iso) => formatDate(iso, getLang());
export const fmtDateTime = (iso) => formatDateTime(iso, getLang());
export const money = (cents, cur = 'USD') => formatMoney(cents, cur, getLang());
export const pct = (x) => Math.round(x * 100) + '%';
export const ago = (iso) => {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 90) return t('just now');
  if (s < 5400) return t('{n} min ago', { n: Math.round(s / 60) });
  if (s < 129600) return t('{n} hours ago', { n: Math.round(s / 3600) });
  return t('{n} days ago', { n: Math.round(s / 86400) });
};

// ---------- toast / errors / busy ----------
let toastTimer;
export function toast(msg, kind = '') {
  document.querySelector('.toast')?.remove();
  const n = div({ class: `toast ${kind}`, role: kind === 'bad' ? 'alert' : 'status' }, msg);
  document.body.append(n);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => n.remove(), kind === 'bad' ? 7000 : 3500);
}
export const toastError = (e) => { toast(t(friendly(e)), 'bad'); if (!e?.code) console.error(e?.name); }; // never log details: they can contain personal data
export async function busy(button, fn) {
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  try { return await fn(); } catch (e) { toastError(e); } finally { button.disabled = false; button.removeAttribute('aria-busy'); }
}
// Wraps a click handler so the button is disabled while work runs and errors become a toast.
export const act = (fn) => (ev) => busy(ev.currentTarget, () => fn(ev));

// ---------- clipboard, share, download, speech ----------
export async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast(t('Copied')); return true; } catch { /* fall through */ }
  const ta = textarea({ value: text, style: { position: 'fixed', opacity: '0' } });
  document.body.append(ta); ta.select();
  let ok = false; try { ok = document.execCommand('copy'); } catch { /* ignore */ }
  ta.remove(); toast(ok ? t('Copied') : t('Could not copy. Select the text and copy it yourself.'), ok ? '' : 'bad');
  return ok;
}
export async function share({ title, text, url }) {
  if (navigator.share) { try { await navigator.share({ title, text, url }); return; } catch (e) { if (e?.name === 'AbortError') return; } }
  await copy([text, url].filter(Boolean).join('\n'));
}
export function download(name, data, type = 'application/octet-stream') {
  const blob = data instanceof Blob ? data : new Blob([data], { type });
  const u = URL.createObjectURL(blob);
  const link = a({ href: u, download: name });
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(u), 10_000);
}
export function speak(text) {
  if (!('speechSynthesis' in window)) return toast(t('Reading aloud is not available on this device.'), 'bad');
  speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.lang = getLang();
  speechSynthesis.speak(u);
}
export const readAloud = (text) => btn(t('Read aloud'), () => speak(text), { kind: 'secondary small' });

// ---------- markdown → DOM (safe subset) ----------
const INLINE = /(\*\*[^*]+\*\*|\*[^*\s][^*]*\*|`[^`]+`|\[[^\]]+\]\([^)\s]+\)|TODO\((?:lawyer|accountant)\):[^\n]*)/;
function inline(s) {
  return s.split(INLINE).filter(Boolean).map((tok) => {
    let m;
    if ((m = /^\*\*([^*]+)\*\*$/.exec(tok))) return strong(m[1]);
    if ((m = /^\*([^*]+)\*$/.exec(tok))) return em(m[1]);
    if ((m = /^`([^`]+)`$/.exec(tok))) return code(m[1]);
    if ((m = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(tok))) {
      return /^(https:\/\/|\/)/.test(m[2]) ? a({ href: m[2], target: m[2].startsWith('/') ? undefined : '_blank', rel: 'noopener noreferrer' }, m[1]) : m[1];
    }
    if (/^TODO\(/.test(tok)) return mark({ class: 'todo' }, tok);
    return tok;
  });
}
export function md(src) {
  const root = div({ class: 'md' });
  const lines = String(src).replace(/\r/g, '').split('\n');
  for (let i = 0; i < lines.length;) {
    const line = lines[i];
    let m;
    if (!line.trim()) { i++; continue; }
    if ((m = /^(#{1,4})\s+(.*)$/.exec(line))) { root.append(h('h' + (m[1].length + 1), null, inline(m[2]))); i++; continue; }
    if (/^---+\s*$/.test(line)) { root.append(hr()); i++; continue; }
    if (/^>/.test(line)) { const q = []; while (i < lines.length && /^>/.test(lines[i])) q.push(lines[i++].replace(/^>\s?/, '')); root.append(blockquote(p(inline(q.join(' '))))); continue; }
    if (/^\s*[-*]\s+/.test(line)) { const items = []; while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) items.push(li(inline(lines[i++].replace(/^\s*[-*]\s+/, '')))); root.append(ul(items)); continue; }
    if (/^\s*\d+\.\s+/.test(line)) { const items = []; while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) items.push(li(inline(lines[i++].replace(/^\s*\d+\.\s+/, '')))); root.append(ol(items)); continue; }
    const para = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,4}\s|>|---+\s*$|\s*[-*]\s+|\s*\d+\.\s+)/.test(lines[i])) para.push(lines[i++].trim());
    root.append(p(inline(para.join(' '))));
  }
  return root;
}
export const fill = (tpl, vars) => tpl.replace(/\{\{(\w+)\}\}/g, (_, k) => (vars[k] ?? `[${k}]`));
// The card body is everything after the <!-- CARD --> marker; the draft banner above it is for lawyers.
export const cardBody = (mdText) => (mdText.includes('<!-- CARD -->') ? mdText.split('<!-- CARD -->')[1] : mdText).trim();

// ---------- routing ----------
const routes = [];
let token = 0;
const root = () => document.getElementById('root');
export function route(pattern, fn) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => (keys.push(k), '([^/]+)')).replace(/\*$/, '.*') + '/?$');
  routes.push({ re, keys, fn });
}
export const fragment = () => new URLSearchParams(location.hash.slice(1));
export const wipers = []; // functions that zero in-memory keys on quick exit
export function setTitle(text, sensitive = false) {
  document.title = sensitive && !store.get('showTitle') ? 'Notes' : `${text} · Project Ludlow`;
}
export async function render() {
  const mine = ++token;
  const path = location.pathname.replace(/\/+$/, '') || '/';
  let found = null;
  for (const r of routes) { const m = r.re.exec(path); if (m) { found = { r, params: Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])])) }; break; } }
  setTitle('Project Ludlow');
  document.getElementById('main')?.setAttribute('aria-busy', 'true');
  try {
    const node = found ? await found.r.fn(found.params) : shell(div({ class: 'wrap' }, h1(t('Page not found')), p(a({ href: '/' }, t('Go to the home page')))));
    if (mine === token) { mount(node); window.scrollTo(0, 0); }
  } catch (e) {
    if (mine === token) mount(shell(div({ class: 'wrap' }, callout('danger', strong(t('That did not work.')), ' ', t(friendly(e))), p(a({ href: '/' }, t('Go to the home page'))))));
  }
}
export function mount(node) { root().replaceChildren(node); }
export function go(path) { history.pushState(null, '', path); render(); }
addEventListener('popstate', render);
document.addEventListener('click', (e) => {
  const link = e.target.closest?.('a[href^="/"]');
  if (link && !link.hasAttribute('download') && link.target !== '_blank' && !e.metaKey && !e.ctrlKey && !e.shiftKey && e.button === 0) {
    e.preventDefault();
    go(link.getAttribute('href'));
  }
});

// The page frame every screen sits in: brand, quick exit, content, honest footer.
export function shell(content, { wide = false, nav: navNode } = {}) {
  return div({ class: 'frame' },
    header({ class: 'top' },
      div({ class: 'top-in' },
        a({ class: 'brand', href: '/' }, span({ class: 'mark', 'aria-hidden': 'true' }, 'L'), span('Project Ludlow')),
        button({ class: 'quick', type: 'button', onclick: quickExit, title: t('Leave this page right now (or press Esc three times)') }, t('Quick exit')))),
    navNode || null,
    div({ id: 'main', class: `page ${wide ? 'wide' : ''}`, tabindex: '-1' }, content),
    footer({ class: 'foot' },
      div({ class: 'foot-in' },
        p({ class: 'small' }, t('Project Ludlow is a tool. It is not a union and not a law firm.')),
        p({ class: 'small links' },
          a({ href: '/protected' }, t('How your data is protected')), ' · ', a({ href: '/rights' }, t('Your rights')), ' · ', a({ href: '/safety' }, t('Safety tips')), ' · ',
          a({ href: '/verify' }, t('Verify this software')), ' · ', a({ href: '/terms' }, t('Terms')), ' · ',
          button({ class: 'linkish', type: 'button', onclick: () => { store.set('showTitle', !store.get('showTitle')); toast(store.get('showTitle') ? t('The tab now shows the app name.') : t('The tab now says "Notes" on private pages.')); } }, t('Tab title')),
          ' · ', langSwitch()))));
}
import { LANGS, setLang } from './i18n.js';
function langSwitch() {
  return select({ 'aria-label': t('Language'), class: 'lang', onchange: (e) => setLang(e.target.value) }, Object.entries(LANGS).map(([k, v]) => option({ value: k, selected: k === getLang() }, v)));
}
export function quickExit() {
  for (const w of wipers) { try { w(); } catch { /* keep wiping */ } }
  try { sessionStorage.clear(); } catch { /* ignore */ }
  location.replace('https://www.wikipedia.org/');
}
let escs = [];
addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  const n = Date.now();
  escs = [...escs.filter((x) => n - x < 1500), n];
  if (escs.length >= 3) quickExit();
});

// A tiny helper for pages with local state: re-renders its own subtree when update() is called.
export function view(fn) {
  const box = div();
  const update = () => box.replaceChildren(fn(update));
  update();
  return box;
}

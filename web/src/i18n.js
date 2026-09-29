// Tiny gettext-style translation. The English sentence IS the key, so code reads naturally and a missing
// translation falls back to English instead of breaking. To add a language: copy es.js, translate the
// values, and register it in DICTS. Right-to-left languages are switched by DIR below.
import es from './es.js';

const DICTS = { es };
export const LANGS = { en: 'English', es: 'Español' };
const DIR = { ar: 'rtl', he: 'rtl', fa: 'rtl', ur: 'rtl' };

const read = () => { try { return localStorage.getItem('ludlow.lang'); } catch { return null; } };
let lang = read() || (navigator.language || 'en').slice(0, 2);
if (!LANGS[lang]) lang = 'en';
document.documentElement.lang = lang;
document.documentElement.dir = DIR[lang] || 'ltr';

export const getLang = () => lang;
export function setLang(l) {
  try { localStorage.setItem('ludlow.lang', l); } catch { /* private window: the choice just won't persist */ }
  location.reload();
}
export function t(s, vars) {
  let out = (DICTS[lang] && DICTS[lang][s]) || s;
  if (vars) out = out.replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? ''));
  return out;
}

// Formatting helpers with no DOM dependency, so they can be unit tested in Node.
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

// A calendar date such as "2026-10-05" has no time zone, so it must show as the SAME day everywhere.
// new Date("2026-10-05") is midnight UTC, which a browser in the Americas would show as Oct 4: an
// off-by-one on a legal deadline. Timestamps with a time of day are shown in the viewer's own zone.
export function formatDate(iso, lang = 'en') {
  if (!iso) return '';
  return DATE_ONLY.test(iso)
    ? new Date(iso + 'T00:00:00Z').toLocaleDateString(lang, { dateStyle: 'medium', timeZone: 'UTC' })
    : new Date(iso).toLocaleDateString(lang, { dateStyle: 'medium' });
}
export const formatDateTime = (iso, lang = 'en') => (iso ? new Date(iso).toLocaleString(lang, { dateStyle: 'medium', timeStyle: 'short' }) : '');
export const formatMoney = (cents, currency = 'USD', lang = 'en') => new Intl.NumberFormat(lang, { style: 'currency', currency }).format((cents || 0) / 100);

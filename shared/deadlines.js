// Grievance deadline engine. Pure functions on YYYY-MM-DD strings (no time-of-day, no DST traps).
// TODO(lawyer): confirm the counting conventions below against the union's actual contract language.
//   - Business days: skip Saturdays, Sundays and configured holidays; day 0 is the start date.
//   - Calendar days: count straight; if the last day lands on a weekend/holiday it rolls to the next business day.
const pad = (n) => String(n).padStart(2, '0');
export const toISO = (d) => `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
export const parseISO = (s) => { const [y, m, d] = s.split('-').map(Number); return new Date(Date.UTC(y, m - 1, d)); };
export const addCalendar = (s, n) => { const d = parseISO(s); d.setUTCDate(d.getUTCDate() + n); return toISO(d); };
export const isBusinessDay = (s, holidays = []) => ![0, 6].includes(parseISO(s).getUTCDay()) && !holidays.includes(s);
export function nextBusinessDay(s, holidays = []) { while (!isBusinessDay(s, holidays)) s = addCalendar(s, 1); return s; }
export function addBusinessDays(s, n, holidays = []) {
  let cur = s;
  for (let left = n; left > 0;) { cur = addCalendar(cur, 1); if (isBusinessDay(cur, holidays)) left--; }
  return cur;
}
export function dueDate(startISO, { days, dayType = 'calendar' }, holidays = []) {
  return dayType === 'business' ? addBusinessDays(startISO, days, holidays) : nextBusinessDay(addCalendar(startISO, days), holidays);
}
export const daysBetween = (a, b) => Math.round((parseISO(b) - parseISO(a)) / 86400000);
export const REMINDER_DAYS = [7, 3, 1, 0];
export function urgency(due, today) {
  const left = daysBetween(today, due);
  return { left, level: left < 0 ? 'overdue' : left === 0 ? 'today' : left <= 3 ? 'soon' : left <= 7 ? 'week' : 'ok' };
}
// Today's calendar date in the union's time zone (en-CA formats as YYYY-MM-DD).
export const todayIn = (tz, now = new Date()) =>
  new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(now);

// Weekly schedule of a category (which weekdays an activity may be logged on).
// Weekdays use the Iranian week: 0 = شنبه (Sat) ... 6 = جمعه (Fri). No date / month / year is involved.

export const DAY_MODES = ['every', 'odd', 'even', 'custom'];

/** "odd" = 1st, 3rd, 5th, 7th day of the week (شنبه، دوشنبه، چهارشنبه، جمعه); "even" = 2nd, 4th, 6th (یکشنبه، سه‌شنبه، پنجشنبه). */
const PRESETS = {
  every: [0, 1, 2, 3, 4, 5, 6],
  odd: [0, 2, 4, 6],
  even: [1, 3, 5],
};

/** yyyy-MM-dd -> 0 (Sat) ... 6 (Fri). */
export function weekdayOf(iso) {
  const d = new Date(`${iso}T00:00:00Z`).getUTCDay(); // 0 = Sunday
  return (d + 1) % 7;
}

export function parseDays(text) {
  const out = String(text ?? '').split(',').map((s) => Number(s.trim()))
    .filter((n) => Number.isInteger(n) && n >= 0 && n <= 6);
  return [...new Set(out)].sort((a, b) => a - b);
}

/**
 * Reads { dayMode, days } from a request body. Returns null when the body does not touch the schedule.
 * Throws a plain Error with a code for invalid input (the caller turns it into HttpError).
 */
export function readSchedule(body) {
  if (body.dayMode === undefined && body.days === undefined) return null;
  const mode = body.dayMode === undefined ? 'custom' : body.dayMode;
  if (!DAY_MODES.includes(mode)) throw new Error('INVALID_DAY_MODE');
  if (mode !== 'custom') return { mode, days: PRESETS[mode] };
  if (!Array.isArray(body.days)) throw new Error('INVALID_DAYS');
  const days = [...new Set(body.days.map(Number))].filter((n) => Number.isInteger(n) && n >= 0 && n <= 6).sort((a, b) => a - b);
  if (days.length === 0) throw new Error('INVALID_DAYS');
  return { mode: 'custom', days };
}

/** Today in Iran (yyyy-MM-dd), whatever the server time zone is. */
export function tehranToday(now = new Date()) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Tehran', year: 'numeric', month: '2-digit', day: '2-digit' }).format(now);
}

export function daysBetween(fromIso, toIso) {
  return Math.round((Date.parse(`${toIso}T00:00:00Z`) - Date.parse(`${fromIso}T00:00:00Z`)) / 86400000);
}

export function addDaysIso(iso, n) {
  return new Date(Date.parse(`${iso}T00:00:00Z`) + n * 86400000).toISOString().slice(0, 10);
}

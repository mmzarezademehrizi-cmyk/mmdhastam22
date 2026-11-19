// Per-user rules the owner can set (stored in users.policy_json). Staff (owner / admin) are never limited.

export const DEFAULT_POLICY = {
  canEditActivities: true,
  canDeleteActivities: true,
  canManageMembers: true,
  allowFutureDates: true,
  maxBackdateDays: null, // null = no limit
  maxHoursPerEntry: null, // null = no extra limit
  allowedCategoryIds: null, // null = every category
};

export function normalizePolicy(input) {
  const p = { ...DEFAULT_POLICY };
  if (!input || typeof input !== 'object') return p;
  for (const k of ['canEditActivities', 'canDeleteActivities', 'canManageMembers', 'allowFutureDates']) {
    if (typeof input[k] === 'boolean') p[k] = input[k];
  }
  if (input.maxBackdateDays !== undefined && input.maxBackdateDays !== null) {
    const n = Number(input.maxBackdateDays);
    if (Number.isInteger(n) && n >= 0 && n <= 3650) p.maxBackdateDays = n;
  }
  if (input.maxHoursPerEntry !== undefined && input.maxHoursPerEntry !== null) {
    const n = Number(input.maxHoursPerEntry);
    if (Number.isFinite(n) && n > 0 && n <= 1000) p.maxHoursPerEntry = Math.round(n * 100) / 100;
  }
  if (Array.isArray(input.allowedCategoryIds)) {
    const ids = [...new Set(input.allowedCategoryIds.map(Number))].filter((n) => Number.isInteger(n) && n > 0);
    p.allowedCategoryIds = ids;
  }
  return p;
}

export function parsePolicy(text) {
  try { return normalizePolicy(JSON.parse(text || '{}')); } catch { return { ...DEFAULT_POLICY }; }
}

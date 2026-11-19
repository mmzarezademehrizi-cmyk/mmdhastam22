import { cfg } from './config.js';
import { getSetting, setSetting, audit } from './db.js';
import { smsProviderReady } from './sms.js';
import { smsEnabled } from './routes_auth.js';
import {
  HttpError, hashPassword, normalizePhone, nowIso, cleanText, isValidNationalId, round2,
} from './util.js';
import { normalizePolicy, parsePolicy } from './policy.js';
import { tehranToday, addDaysIso } from './schedule.js';

const STAFF = ['owner', 'admin'];

/** Optional info the owner can store about a user (free text, all optional). */
export const PROFILE_KEYS = [
  'father_name', 'national_id', 'birth_date', 'gender', 'email', 'address', 'city',
  'job', 'second_phone', 'emergency_name', 'emergency_phone', 'notes',
];
/** Optional info about the user's phone. */
export const DEVICE_KEYS = [
  'device_brand', 'device_model', 'os_version', 'imei', 'sim_number', 'sim_carrier', 'device_notes',
];

function pickKeys(obj, keys) {
  const out = {};
  if (!obj || typeof obj !== 'object') return out;
  for (const k of keys) {
    const v = cleanText(obj[k], k === 'address' || k === 'notes' || k === 'device_notes' ? 1000 : 200);
    if (v) out[k] = v;
  }
  return out;
}

function canManage(actorRole, targetRole) {
  if (actorRole === 'owner') return true;
  return actorRole === 'admin' && (targetRole === 'user' || targetRole === 'operator');
}

function parseJson(text) {
  try { return JSON.parse(text || '{}'); } catch { return {}; }
}

function fullUser(row) {
  return {
    id: row.id,
    phone: row.phone,
    firstName: row.first_name,
    lastName: row.last_name,
    role: row.role,
    isActive: row.is_active === 1,
    hasPassword: Boolean(row.password_hash),
    mustSetPassword: row.must_set_password === 1,
    profile: parseJson(row.profile_json),
    device: parseJson(row.device_json),
    policy: parsePolicy(row.policy_json),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function checkPassword(p) {
  if (typeof p !== 'string' || p.length < cfg.passwordMin || p.length > cfg.passwordMax) {
    throw new HttpError(400, 'INVALID_PASSWORD', { minLength: cfg.passwordMin });
  }
  return p;
}

function checkProfile(profile) {
  if (profile.national_id && !isValidNationalId(profile.national_id)) throw new HttpError(400, 'INVALID_NATIONAL_ID');
}

export function registerOwnerRoutes(router) {
  // ───── settings (SMS login switch) ─────
  router.add('GET', '/owner/settings', { auth: true, roles: STAFF }, async (ctx) => ({
    smsLoginEnabled: await smsEnabled(ctx.db),
    smsProvider: cfg.smsProvider,
    smsProviderReady: smsProviderReady(),
    canChange: ctx.user.role === 'owner',
  }));

  router.add('PUT', '/owner/settings', { auth: true, roles: ['owner'] }, async (ctx) => {
    if (typeof ctx.body.smsLoginEnabled !== 'boolean') throw new HttpError(400, 'INVALID_BODY', { field: 'smsLoginEnabled' });
    await setSetting(ctx.db, 'sms_login_enabled', ctx.body.smsLoginEnabled ? '1' : '0');
    await audit(ctx.db, ctx.user.id, 'settings.sms_login', 'settings', 'sms_login_enabled', { enabled: ctx.body.smsLoginEnabled });
    return { smsLoginEnabled: ctx.body.smsLoginEnabled };
  });

  // ───── users ─────
  router.add('GET', '/owner/users', { auth: true, roles: STAFF }, async (ctx) => {
    const rows = (await ctx.db.prepare(`
      SELECT u.id, u.phone, u.first_name, u.last_name, u.role, u.is_active, u.password_hash, u.must_set_password,
             p.last_seen_at,
             (SELECT MAX(activity_date) FROM activities WHERE created_by = u.id) AS last_activity_date,
             (SELECT COUNT(*) FROM activities WHERE created_by = u.id AND activity_date >= ?) AS activities_7d
      FROM users u LEFT JOIN presence p ON p.user_id = u.id
      ORDER BY u.last_name, u.first_name`).all(addDaysIso(tehranToday(), -6)));
    const cutoff = Date.now() - 2 * 60 * 1000;
    return rows.map((r) => ({
      id: r.id,
      phone: r.phone,
      firstName: r.first_name,
      lastName: r.last_name,
      role: r.role,
      isActive: r.is_active === 1,
      hasPassword: Boolean(r.password_hash),
      mustSetPassword: r.must_set_password === 1,
      lastSeenAt: r.last_seen_at,
      online: r.last_seen_at ? Date.parse(r.last_seen_at) >= cutoff : false,
      lastActivityDate: r.last_activity_date,
      activities7d: r.activities_7d,
    }));
  });

  router.add('GET', '/owner/users/:id', { auth: true, roles: STAFF }, async (ctx) => {
    const row = (await ctx.db.prepare('SELECT * FROM users WHERE id = ?').get(Number(ctx.params.id)));
    if (!row) throw new HttpError(404, 'NOT_FOUND');
    return fullUser(row);
  });

  router.add('POST', '/owner/users', { auth: true, roles: STAFF }, async (ctx) => {
    const b = ctx.body;
    const phone = normalizePhone(b.phone);
    if (!phone) throw new HttpError(400, 'INVALID_PHONE');
    const firstName = cleanText(b.firstName, 80);
    const lastName = cleanText(b.lastName, 80);
    if (!firstName || !lastName) throw new HttpError(400, 'INVALID_BODY', { field: 'name' });
    const role = ['user', 'operator', 'admin'].includes(b.role) ? b.role : 'user';
    if (!canManage(ctx.user.role, role)) throw new HttpError(403, 'ROLE_NOT_ALLOWED');
    const profile = pickKeys(b.profile, PROFILE_KEYS);
    const device = pickKeys(b.device, DEVICE_KEYS);
    checkProfile(profile);

    const db = ctx.db;
    if ((await db.prepare('SELECT 1 FROM users WHERE phone = ?').get(phone))) throw new HttpError(409, 'PHONE_ALREADY_EXISTS');

    let passwordHash = null;
    let mustSet = 1;
    if (b.password !== undefined && b.password !== null && b.password !== '') {
      passwordHash = await hashPassword(checkPassword(b.password));
      mustSet = b.forcePasswordChange === false ? 0 : 1;
    }
    const now = nowIso();
    const id = (await db.prepare(`INSERT INTO users(phone, first_name, last_name, role, is_active, password_hash, must_set_password,
        password_updated_at, profile_json, device_json, created_by, created_at, updated_at)
        VALUES(?,?,?,?,1,?,?,?,?,?,?,?,?)`)
      .run(phone, firstName, lastName, role, passwordHash, mustSet, passwordHash ? now : null,
        JSON.stringify(profile), JSON.stringify(device), ctx.user.id, now, now)).lastInsertRowid;
    await audit(db, ctx.user.id, 'user.created', 'user', id, { role, withPassword: Boolean(passwordHash) });
    return [201, fullUser((await db.prepare('SELECT * FROM users WHERE id = ?').get(id)))];
  });

  router.add('PUT', '/owner/users/:id', { auth: true, roles: STAFF }, async (ctx) => {
    const db = ctx.db;
    const id = Number(ctx.params.id);
    const row = (await db.prepare('SELECT * FROM users WHERE id = ?').get(id));
    if (!row) throw new HttpError(404, 'NOT_FOUND');
    if (!canManage(ctx.user.role, row.role) && row.id !== ctx.user.id) throw new HttpError(403, 'ROLE_NOT_ALLOWED');
    const b = ctx.body;

    const phone = b.phone !== undefined ? normalizePhone(b.phone) : row.phone;
    if (!phone) throw new HttpError(400, 'INVALID_PHONE');
    if (phone !== row.phone && (await db.prepare('SELECT 1 FROM users WHERE phone = ? AND id != ?').get(phone, id))) {
      throw new HttpError(409, 'PHONE_ALREADY_EXISTS');
    }
    const firstName = b.firstName !== undefined ? cleanText(b.firstName, 80) : row.first_name;
    const lastName = b.lastName !== undefined ? cleanText(b.lastName, 80) : row.last_name;
    if (!firstName || !lastName) throw new HttpError(400, 'INVALID_BODY', { field: 'name' });

    let role = row.role;
    if (b.role !== undefined && b.role !== row.role) {
      if (id === ctx.user.id) throw new HttpError(400, 'CANNOT_CHANGE_OWN_ROLE');
      if (!['user', 'operator', 'admin', 'owner'].includes(b.role)) throw new HttpError(400, 'INVALID_BODY', { field: 'role' });
      if (!canManage(ctx.user.role, b.role)) throw new HttpError(403, 'ROLE_NOT_ALLOWED');
      role = b.role;
    }
    let isActive = row.is_active;
    if (b.isActive !== undefined) {
      if (id === ctx.user.id && b.isActive === false) throw new HttpError(400, 'CANNOT_DISABLE_SELF');
      isActive = b.isActive ? 1 : 0;
    }
    const profile = b.profile !== undefined ? pickKeys(b.profile, PROFILE_KEYS) : parseJson(row.profile_json);
    const device = b.device !== undefined ? pickKeys(b.device, DEVICE_KEYS) : parseJson(row.device_json);
    checkProfile(profile);

    const stmts = [
      db.prepare('UPDATE users SET phone=?, first_name=?, last_name=?, role=?, is_active=?, profile_json=?, device_json=?, updated_at=? WHERE id=?')
        .bind(phone, firstName, lastName, role, isActive, JSON.stringify(profile), JSON.stringify(device), nowIso(), id),
    ];
    if (isActive === 0 || phone !== row.phone) {
      stmts.push(db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(nowIso(), id));
    }
    await db.batch(stmts);
    await audit(db, ctx.user.id, 'user.updated', 'user', id);
    return fullUser((await db.prepare('SELECT * FROM users WHERE id = ?').get(id)));
  });

  // Owner/admin sets a password for the user ("forceChange": user must pick their own at next login).
  router.add('POST', '/owner/users/:id/set-password', { auth: true, roles: STAFF }, async (ctx) => {
    const db = ctx.db;
    const id = Number(ctx.params.id);
    const row = (await db.prepare('SELECT id, role FROM users WHERE id = ?').get(id));
    if (!row) throw new HttpError(404, 'NOT_FOUND');
    if (!canManage(ctx.user.role, row.role)) throw new HttpError(403, 'ROLE_NOT_ALLOWED');
    const hash = await hashPassword(checkPassword(ctx.body.password));
    const mustSet = ctx.body.forceChange === false ? 0 : 1;
    await db.batch([
      db.prepare('UPDATE users SET password_hash=?, must_set_password=?, password_updated_at=?, failed_login_count=0, locked_until=NULL, updated_at=? WHERE id=?')
        .bind(hash, mustSet, nowIso(), nowIso(), id),
      db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(nowIso(), id),
    ]);
    await audit(db, ctx.user.id, 'auth.password_set_by_staff', 'user', id, { forceChange: mustSet === 1 });
    return { ok: true };
  });

  // Forgot password: clears it; the user then needs a new password from staff, or SMS login if enabled.
  router.add('POST', '/owner/users/:id/reset-password', { auth: true, roles: STAFF }, async (ctx) => {
    const db = ctx.db;
    const id = Number(ctx.params.id);
    const row = (await db.prepare('SELECT id, role FROM users WHERE id = ?').get(id));
    if (!row) throw new HttpError(404, 'NOT_FOUND');
    if (!canManage(ctx.user.role, row.role)) throw new HttpError(403, 'ROLE_NOT_ALLOWED');
    await db.batch([
      db.prepare('UPDATE users SET password_hash=NULL, must_set_password=1, failed_login_count=0, locked_until=NULL, updated_at=? WHERE id=?')
        .bind(nowIso(), id),
      db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(nowIso(), id),
    ]);
    await audit(db, ctx.user.id, 'auth.password_reset', 'user', id);
    return { ok: true };
  });


  // ───── per-user rules (what the user may do) ─────
  router.add('PUT', '/owner/users/:id/policy', { auth: true, roles: STAFF }, async (ctx) => {
    const db = ctx.db;
    const id = Number(ctx.params.id);
    const row = (await db.prepare('SELECT id, role FROM users WHERE id = ?').get(id));
    if (!row) throw new HttpError(404, 'NOT_FOUND');
    if (!canManage(ctx.user.role, row.role)) throw new HttpError(403, 'ROLE_NOT_ALLOWED');
    const policy = normalizePolicy(ctx.body.policy ?? ctx.body);
    (await db.prepare('UPDATE users SET policy_json = ?, updated_at = ? WHERE id = ?').run(JSON.stringify(policy), nowIso(), id));
    await audit(db, ctx.user.id, 'user.policy_changed', 'user', id, policy);
    return { policy };
  });

  // Sign the user out of every device.
  router.add('POST', '/owner/users/:id/logout-all', { auth: true, roles: STAFF }, async (ctx) => {
    const db = ctx.db;
    const id = Number(ctx.params.id);
    const row = (await db.prepare('SELECT id, role FROM users WHERE id = ?').get(id));
    if (!row) throw new HttpError(404, 'NOT_FOUND');
    if (!canManage(ctx.user.role, row.role)) throw new HttpError(403, 'ROLE_NOT_ALLOWED');
    const n = (await db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(nowIso(), id)).changes;
    await audit(db, ctx.user.id, 'auth.logout_all', 'user', id, { sessions: Number(n) });
    return { ok: true, revoked: Number(n) };
  });

  // Overview of one user: activity stats + login info.
  router.add('GET', '/owner/users/:id/overview', { auth: true, roles: STAFF }, async (ctx) => {
    const db = ctx.db;
    const id = Number(ctx.params.id);
    const u = (await db.prepare('SELECT * FROM users WHERE id = ?').get(id));
    if (!u) throw new HttpError(404, 'NOT_FOUND');
    const today = tehranToday();
    const monthStart = `${today.slice(0, 8)}01`; // Gregorian month start; the app sends Jalali ranges itself when needed
    const stats = async (from) => (await db.prepare(`
      SELECT COUNT(DISTINCT a.id) AS activities, COUNT(DISTINCT e.member_id) AS members,
             COALESCE(SUM(e.raw_hours), 0) AS raw_hours, COALESCE(SUM(e.final_hours), 0) AS final_hours
      FROM activities a LEFT JOIN activity_entries e ON e.activity_id = a.id
      WHERE a.created_by = ? AND a.activity_date >= ?`).get(id, from));
    const fmt = (r) => ({ activities: r.activities, members: r.members, rawHours: round2(r.raw_hours), finalHours: round2(r.final_hours) });
    const last = (await db.prepare('SELECT activity_date, created_at FROM activities WHERE created_by = ? ORDER BY id DESC LIMIT 1').get(id));
    const presence = (await db.prepare('SELECT last_seen_at FROM presence WHERE user_id = ?').get(id));
    const sess = (await db.prepare(`SELECT COUNT(*) AS n, MAX(created_at) AS last_login FROM sessions
      WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?`).get(id, nowIso()));
    const lastLogin = (await db.prepare("SELECT created_at FROM audit_logs WHERE action = 'auth.login' AND entity_id = ? ORDER BY id DESC LIMIT 1").get(String(id)));
    const membersTotal = (await db.prepare('SELECT COUNT(*) AS c FROM members WHERE created_by = ?').get(id)).c;
    return {
      user: fullUser(u),
      lastSeenAt: presence?.last_seen_at ?? null,
      online: presence ? Date.parse(presence.last_seen_at) >= Date.now() - 120000 : false,
      activeSessions: sess.n,
      lastLoginAt: lastLogin?.created_at ?? sess.last_login ?? null,
      membersTotal,
      last7Days: fmt(await stats(addDaysIso(today, -6))),
      last30Days: fmt(await stats(addDaysIso(today, -29))),
      thisMonthGregorian: fmt(await stats(monthStart)),
      lastActivity: last ? { date: last.activity_date, createdAt: last.created_at } : null,
    };
  });

  // Who did what (newest first). Optional: userId (actor or target), limit, before (id).
  router.add('GET', '/owner/activity-log', { auth: true, roles: STAFF }, async (ctx) => {
    const limit = Math.min(Math.max(Number(ctx.query.limit) || 50, 1), 200);
    const where = [];
    const args = [];
    if (ctx.query.userId) {
      where.push("(l.actor_id = ? OR (l.entity_type = 'user' AND l.entity_id = ?))");
      args.push(Number(ctx.query.userId), String(Number(ctx.query.userId)));
    }
    if (ctx.query.before) { where.push('l.id < ?'); args.push(Number(ctx.query.before)); }
    const rows = (await ctx.db.prepare(`
      SELECT l.id, l.actor_id, l.action, l.entity_type, l.entity_id, l.details, l.created_at,
             u.first_name || ' ' || u.last_name AS actor_name
      FROM audit_logs l LEFT JOIN users u ON u.id = l.actor_id
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY l.id DESC LIMIT ${limit}`).all(...args));
    return rows.map((r) => ({
      id: r.id, actorId: r.actor_id, actorName: r.actor_name, action: r.action,
      entityType: r.entity_type, entityId: r.entity_id, details: parseJson(r.details), createdAt: r.created_at,
    }));
  });

  // Owner dashboard: today at a glance.
  router.add('GET', '/owner/dashboard', { auth: true, roles: STAFF }, async (ctx) => {
    const db = ctx.db;
    const today = tehranToday();
    const weekAgo = addDaysIso(today, -6);
    const cutoff = new Date(Date.now() - 120000).toISOString();
    const users = (await db.prepare(`SELECT COUNT(*) AS total, COALESCE(SUM(is_active), 0) AS active FROM users`).get());
    const online = (await db.prepare('SELECT COUNT(*) AS c FROM presence p JOIN users u ON u.id = p.user_id WHERE p.last_seen_at >= ? AND u.is_active = 1').get(cutoff)).c;
    const agg = async (from, to) => {
      const r = (await db.prepare(`
        SELECT COUNT(DISTINCT a.id) AS activities, COUNT(e.id) AS entries, COALESCE(SUM(e.final_hours), 0) AS final_hours
        FROM activities a LEFT JOIN activity_entries e ON e.activity_id = a.id
        WHERE a.activity_date >= ? AND a.activity_date <= ?`).get(from, to));
      return { activities: r.activities, entries: r.entries, finalHours: round2(r.final_hours) };
    };
    const top = (await db.prepare(`
      SELECT u.id, u.first_name || ' ' || u.last_name AS name, COUNT(DISTINCT a.id) AS activities, COALESCE(SUM(e.final_hours), 0) AS final_hours
      FROM activities a JOIN users u ON u.id = a.created_by LEFT JOIN activity_entries e ON e.activity_id = a.id
      WHERE a.activity_date >= ? AND a.activity_date <= ?
      GROUP BY u.id ORDER BY final_hours DESC LIMIT 5`).all(weekAgo, today))
      .map((r) => ({ userId: r.id, name: r.name, activities: r.activities, finalHours: round2(r.final_hours) }));
    const inactive = (await db.prepare(`
      SELECT u.id, u.first_name || ' ' || u.last_name AS name,
             (SELECT MAX(activity_date) FROM activities WHERE created_by = u.id) AS last_date
      FROM users u
      WHERE u.is_active = 1 AND u.role IN ('user', 'operator')
        AND NOT EXISTS (SELECT 1 FROM activities a WHERE a.created_by = u.id AND a.activity_date >= ?)
      ORDER BY last_date IS NULL DESC, last_date ASC LIMIT 20`).all(weekAgo))
      .map((r) => ({ userId: r.id, name: r.name, lastActivityDate: r.last_date }));
    return {
      today,
      users: { total: users.total, active: users.active, online },
      todayStats: await agg(today, today),
      weekStats: await agg(weekAgo, today),
      topUsers: top,
      inactiveUsers: inactive,
    };
  });

  router.add('GET', '/owner/info-fields', { auth: true, roles: STAFF }, () => ({ profile: PROFILE_KEYS, device: DEVICE_KEYS }));
}

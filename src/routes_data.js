import { audit } from './db.js';
import {
  HttpError, applyRule, cleanText, isIsoDate, isValidNationalId, nowIso, round2,
} from './util.js';
import { parseDays, readSchedule, weekdayOf, tehranToday, daysBetween } from './schedule.js';
import { parsePolicy } from './policy.js';

const ALL = ['owner', 'admin', 'operator', 'user'];
const STAFF = ['owner', 'admin'];

/** role "user" only sees/changes what he created; operator, admin, owner see everything. */
const scoped = (ctx) => ctx.user.role === 'user';

/** Rules the owner set for this user (owner / admin are never limited). */
export async function policyOf(ctx) {
  if (STAFF.includes(ctx.user.role)) return null;
  const row = (await ctx.db.prepare('SELECT policy_json FROM users WHERE id = ?').get(ctx.user.id));
  return parsePolicy(row?.policy_json);
}

async function requireFlag(ctx, flag) {
  const pol = await policyOf(ctx);
  if (pol && pol[flag] === false) throw new HttpError(403, 'NOT_ALLOWED_BY_OWNER');
}

function scheduleInput(body) {
  try { return readSchedule(body); } catch (e) { throw new HttpError(400, e.message); }
}

function categoryRow(r) {
  return { id: r.id, title: r.title, is_active: r.is_active, sort_order: r.sort_order, day_mode: r.day_mode, days: parseDays(r.days) };
}

function intParam(v) {
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0) throw new HttpError(400, 'INVALID_ID');
  return n;
}

function normNid(v) {
  const s = cleanText(v, 20)
    .replace(/[۰-۹]/g, (d) => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d)))
    .replace(/[٠-٩]/g, (d) => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)));
  if (!s) return null;
  if (!isValidNationalId(s)) throw new HttpError(400, 'INVALID_NATIONAL_ID');
  return s;
}

function memberInput(b) {
  const first = cleanText(b.firstName, 80);
  const last = cleanText(b.lastName, 80);
  if (!first || !last) throw new HttpError(400, 'INVALID_BODY', { field: 'name' });
  return { first, last, father: cleanText(b.fatherName, 80) || null, nid: normNid(b.nationalId) };
}

async function getMember(ctx, id) {
  const m = (await ctx.db.prepare('SELECT * FROM members WHERE id = ?').get(id));
  if (!m || (scoped(ctx) && m.created_by !== ctx.user.id)) throw new HttpError(404, 'NOT_FOUND');
  return m;
}

async function ruleAt(db, categoryId, date) {
  return (await db.prepare(`SELECT * FROM calculation_rules WHERE category_id = ? AND effective_from <= ?
    ORDER BY effective_from DESC, version DESC LIMIT 1`).get(categoryId, date));
}

async function readActivityBody(ctx, existingId) {
  const b = ctx.body;
  const categoryId = intParam(b.categoryId);
  if (!isIsoDate(b.date)) throw new HttpError(400, 'INVALID_DATE');
  const note = cleanText(b.note, 1000) || null;
  if (!Array.isArray(b.entries) || b.entries.length === 0 || b.entries.length > 1000) throw new HttpError(400, 'NO_ENTRIES');
  const seen = new Set();
  const entries = b.entries.map((e) => {
    const memberId = intParam(e?.memberId);
    const raw = Number(e?.rawHours);
    if (!Number.isFinite(raw) || raw <= 0 || raw > 1000) throw new HttpError(400, 'INVALID_HOURS');
    if (seen.has(memberId)) throw new HttpError(400, 'DUPLICATE_MEMBER');
    seen.add(memberId);
    return { memberId, raw: round2(raw) };
  });
  const cat = (await ctx.db.prepare('SELECT id, is_active FROM categories WHERE id = ?').get(categoryId));
  if (!cat) throw new HttpError(400, 'CATEGORY_NOT_FOUND');
  if (!cat.is_active && !existingId) throw new HttpError(400, 'CATEGORY_INACTIVE');
  for (const e of entries) await getMember(ctx, e.memberId); // role "user" may only use his own members
  return { categoryId, date: b.date, note, entries };
}

/** Day / date / hour limits for users who are not staff. Only checked when the date or category is new. */
async function enforceActivityRules(ctx, v, existing) {
  if (STAFF.includes(ctx.user.role)) return;
  const pol = await policyOf(ctx);
  const changed = !existing || existing.category_id !== v.categoryId || existing.activity_date !== v.date;
  if (changed) {
    if (pol.allowedCategoryIds && !pol.allowedCategoryIds.includes(v.categoryId)) throw new HttpError(403, 'CATEGORY_NOT_ALLOWED');
    const cat = (await ctx.db.prepare('SELECT days FROM categories WHERE id = ?').get(v.categoryId));
    const days = parseDays(cat.days);
    if (!days.includes(weekdayOf(v.date))) throw new HttpError(400, 'DAY_NOT_ALLOWED', { allowedDays: days });
    const ago = daysBetween(v.date, tehranToday()); // > 0 = in the past
    if (ago < 0 && !pol.allowFutureDates) throw new HttpError(400, 'FUTURE_DATE_NOT_ALLOWED');
    if (pol.maxBackdateDays !== null && ago > pol.maxBackdateDays) throw new HttpError(400, 'DATE_TOO_OLD', { maxBackdateDays: pol.maxBackdateDays });
  }
  if (pol.maxHoursPerEntry !== null) {
    for (const e of v.entries) if (e.raw > pol.maxHoursPerEntry) throw new HttpError(400, 'HOURS_LIMIT_EXCEEDED', { maxHours: pol.maxHoursPerEntry });
  }
}

/** Insert statements for the hours of an activity (D1 allows ~100 bound values per query -> 15 rows each). */
async function entryStatements(db, activityId, categoryId, date, entries) {
  const rule = await ruleAt(db, categoryId, date);
  const now = nowIso();
  const stmts = [];
  for (let i = 0; i < entries.length; i += 15) {
    const chunk = entries.slice(i, i + 15);
    const args = [];
    for (const e of chunk) args.push(activityId, e.memberId, e.raw, rule ? rule.id : null, applyRule(rule, e.raw), now);
    stmts.push(db.prepare(
      'INSERT INTO activity_entries(activity_id, member_id, raw_hours, applied_rule_id, final_hours, created_at) VALUES '
      + chunk.map(() => '(?,?,?,?,?,?)').join(',')).bind(...args));
  }
  return stmts;
}

export function registerDataRoutes(router) {
  // ───────────── members ─────────────
  router.add('GET', '/members', { auth: true, roles: ALL }, async (ctx) => {
    const sql = 'SELECT id, first_name, last_name, father_name, national_id FROM members' +
      (scoped(ctx) ? ' WHERE created_by = ?' : '') + ' ORDER BY last_name, first_name';
    return scoped(ctx) ? (await ctx.db.prepare(sql).all(ctx.user.id)) : (await ctx.db.prepare(sql).all());
  });

  router.add('POST', '/members', { auth: true, roles: ALL }, async (ctx) => {
    await requireFlag(ctx, 'canManageMembers');
    const m = memberInput(ctx.body);
    if (m.nid && (await ctx.db.prepare('SELECT 1 FROM members WHERE national_id = ?').get(m.nid))) throw new HttpError(409, 'DUPLICATE_NATIONAL_ID');
    const now = nowIso();
    const id = (await ctx.db.prepare('INSERT INTO members(created_by, first_name, last_name, father_name, national_id, created_at, updated_at) VALUES(?,?,?,?,?,?,?)')
      .run(ctx.user.id, m.first, m.last, m.father, m.nid, now, now)).lastInsertRowid;
    return [201, { id }];
  });

  router.add('POST', '/members/bulk', { auth: true, roles: ALL }, async (ctx) => {
    await requireFlag(ctx, 'canManageMembers');
    const list = ctx.body.members;
    if (!Array.isArray(list) || list.length === 0 || list.length > 500) throw new HttpError(400, 'INVALID_BODY');
    let skipped = 0;
    const now = nowIso();
    const rows = [];
    const seenNid = new Set();
    for (const item of list) {
      let m;
      try { m = memberInput(item || {}); } catch { skipped++; continue; }
      if (m.nid) {
        if (seenNid.has(m.nid)) { skipped++; continue; }
        seenNid.add(m.nid);
      }
      rows.push(m);
    }
    // national ids that already exist (D1 allows ~100 bound values per query)
    const existing = new Set();
    const nids = rows.filter((r) => r.nid).map((r) => r.nid);
    for (let i = 0; i < nids.length; i += 90) {
      const part = nids.slice(i, i + 90);
      const found = await ctx.db.prepare(`SELECT national_id FROM members WHERE national_id IN (${part.map(() => '?').join(',')})`).all(...part);
      for (const f of found) existing.add(f.national_id);
    }
    const fresh = rows.filter((r) => !r.nid || !existing.has(r.nid));
    skipped += rows.length - fresh.length;
    const stmts = [];
    for (let i = 0; i < fresh.length; i += 14) {
      const chunk = fresh.slice(i, i + 14);
      const args = [];
      for (const m of chunk) args.push(ctx.user.id, m.first, m.last, m.father, m.nid, now, now);
      stmts.push(ctx.db.prepare(
        'INSERT INTO members(created_by, first_name, last_name, father_name, national_id, created_at, updated_at) VALUES '
        + chunk.map(() => '(?,?,?,?,?,?,?)').join(',')).bind(...args));
    }
    await ctx.db.batch(stmts);
    const added = fresh.length;
    return { added, skipped };
  });

  router.add('PUT', '/members/:id', { auth: true, roles: ALL }, async (ctx) => {
    await requireFlag(ctx, 'canManageMembers');
    const cur = await getMember(ctx, intParam(ctx.params.id));
    const m = memberInput(ctx.body);
    if (m.nid && (await ctx.db.prepare('SELECT 1 FROM members WHERE national_id = ? AND id != ?').get(m.nid, cur.id))) throw new HttpError(409, 'DUPLICATE_NATIONAL_ID');
    (await ctx.db.prepare('UPDATE members SET first_name=?, last_name=?, father_name=?, national_id=?, updated_at=? WHERE id=?')
      .run(m.first, m.last, m.father, m.nid, nowIso(), cur.id));
    return { ok: true };
  });

  router.add('GET', '/members/:id/usage', { auth: true, roles: ALL }, async (ctx) => {
    const m = await getMember(ctx, intParam(ctx.params.id));
    return { count: (await ctx.db.prepare('SELECT COUNT(*) AS c FROM activity_entries WHERE member_id = ?').get(m.id)).c };
  });

  router.add('DELETE', '/members/:id', { auth: true, roles: ALL }, async (ctx) => {
    await requireFlag(ctx, 'canManageMembers');
    const m = await getMember(ctx, intParam(ctx.params.id));
    const count = (await ctx.db.prepare('SELECT COUNT(*) AS c FROM activity_entries WHERE member_id = ?').get(m.id)).c;
    if (count > 0) throw new HttpError(409, 'MEMBER_IN_USE', { count });
    (await ctx.db.prepare('DELETE FROM members WHERE id = ?').run(m.id));
    return { ok: true };
  });

  // ───────────── categories & rules ─────────────
  router.add('GET', '/categories', { auth: true, roles: ALL }, async (ctx) => {
    const rows = (await ctx.db.prepare('SELECT id, title, is_active, sort_order, day_mode, days FROM categories ORDER BY sort_order, id').all()).map(categoryRow);
    const pol = await policyOf(ctx);
    return pol && pol.allowedCategoryIds ? rows.filter((c) => pol.allowedCategoryIds.includes(c.id)) : rows;
  });

  // The rules the signed-in user has to follow (the app hides buttons accordingly; the server enforces them).
  router.add('GET', '/me/policy', { auth: true, roles: ALL }, async (ctx) => {
    const pol = await policyOf(ctx);
    return { limited: pol !== null, policy: pol };
  });

  router.add('POST', '/categories', { auth: true, roles: STAFF }, async (ctx) => {
    const title = cleanText(ctx.body.title, 120);
    if (!title) throw new HttpError(400, 'INVALID_BODY', { field: 'title' });
    const sch = scheduleInput(ctx.body) || { mode: 'every', days: [0, 1, 2, 3, 4, 5, 6] };
    const next = (await ctx.db.prepare('SELECT COALESCE(MAX(sort_order), 0) + 1 AS n FROM categories').get()).n;
    const id = (await ctx.db.prepare('INSERT INTO categories(title, is_active, sort_order, created_at, day_mode, days) VALUES(?,?,?,?,?,?)')
      .run(title, ctx.body.isActive === false ? 0 : 1, next, nowIso(), sch.mode, sch.days.join(','))).lastInsertRowid;
    await audit(ctx.db, ctx.user.id, 'category.created', 'category', id, { title, dayMode: sch.mode, days: sch.days });
    return [201, { id }];
  });

  router.add('PUT', '/categories/:id', { auth: true, roles: STAFF }, async (ctx) => {
    const id = intParam(ctx.params.id);
    const cur = (await ctx.db.prepare('SELECT * FROM categories WHERE id = ?').get(id));
    if (!cur) throw new HttpError(404, 'NOT_FOUND');
    const title = ctx.body.title !== undefined ? cleanText(ctx.body.title, 120) : cur.title;
    if (!title) throw new HttpError(400, 'INVALID_BODY', { field: 'title' });
    const active = ctx.body.isActive !== undefined ? (ctx.body.isActive ? 1 : 0) : cur.is_active;
    const sch = scheduleInput(ctx.body);
    const mode = sch ? sch.mode : cur.day_mode;
    const days = sch ? sch.days.join(',') : cur.days;
    (await ctx.db.prepare('UPDATE categories SET title=?, is_active=?, day_mode=?, days=? WHERE id=?').run(title, active, mode, days, id));
    if (sch) await audit(ctx.db, ctx.user.id, 'category.schedule_changed', 'category', id, { title, dayMode: sch.mode, days: sch.days });
    return { ok: true };
  });

  router.add('GET', '/categories/:id/usage', { auth: true, roles: ALL }, async (ctx) => ({
    count: (await ctx.db.prepare('SELECT COUNT(*) AS c FROM activities WHERE category_id = ?').get(intParam(ctx.params.id))).c,
  }));

  router.add('DELETE', '/categories/:id', { auth: true, roles: STAFF }, async (ctx) => {
    const id = intParam(ctx.params.id);
    const count = (await ctx.db.prepare('SELECT COUNT(*) AS c FROM activities WHERE category_id = ?').get(id)).c;
    if (count > 0) throw new HttpError(409, 'CATEGORY_IN_USE', { count });
    (await ctx.db.prepare('DELETE FROM categories WHERE id = ?').run(id));
    await audit(ctx.db, ctx.user.id, 'category.deleted', 'category', id);
    return { ok: true };
  });

  router.add('GET', '/categories/:id/rules', { auth: true, roles: ALL }, async (ctx) =>
    (await ctx.db.prepare('SELECT id, category_id, version, operation, add_hours, multiplier, effective_from FROM calculation_rules WHERE category_id = ? ORDER BY version DESC')
      .all(intParam(ctx.params.id))));

  router.add('GET', '/categories/:id/rule-at', { auth: true, roles: ALL }, async (ctx) => {
    if (!isIsoDate(ctx.query.date)) throw new HttpError(400, 'INVALID_DATE');
    const r = await ruleAt(ctx.db, intParam(ctx.params.id), ctx.query.date);
    return r ? { rule: { id: r.id, category_id: r.category_id, version: r.version, operation: r.operation, add_hours: r.add_hours, multiplier: r.multiplier, effective_from: r.effective_from } } : { rule: null };
  });

  // Rules are never edited, only new versions are added.
  router.add('POST', '/categories/:id/rules', { auth: true, roles: STAFF }, async (ctx) => {
    const id = intParam(ctx.params.id);
    if (!(await ctx.db.prepare('SELECT 1 FROM categories WHERE id = ?').get(id))) throw new HttpError(404, 'NOT_FOUND');
    const b = ctx.body;
    if (!['none', 'add', 'multiply', 'add_then_multiply'].includes(b.operation)) throw new HttpError(400, 'INVALID_OPERATION');
    if (!isIsoDate(b.effectiveFrom)) throw new HttpError(400, 'INVALID_DATE');
    const add = b.operation === 'add' || b.operation === 'add_then_multiply' ? Number(b.addHours) : 0;
    const mul = b.operation === 'multiply' || b.operation === 'add_then_multiply' ? Number(b.multiplier) : 1;
    if (!Number.isFinite(add) || add < 0 || add > 1000) throw new HttpError(400, 'INVALID_ADD_HOURS');
    if (!Number.isFinite(mul) || mul <= 0 || mul > 1000) throw new HttpError(400, 'INVALID_MULTIPLIER');
    await ctx.db.prepare(`INSERT INTO calculation_rules(category_id, version, operation, add_hours, multiplier, effective_from, created_by, created_at)
      SELECT ?, COALESCE(MAX(version), 0) + 1, ?, ?, ?, ?, ?, ? FROM calculation_rules WHERE category_id = ?`)
      .run(id, b.operation, add, mul, b.effectiveFrom, ctx.user.id, nowIso(), id);
    await audit(ctx.db, ctx.user.id, 'rule.added', 'category', id, { operation: b.operation });
    return [201, { ok: true }];
  });

  // ───────────── activities ─────────────
  router.add('GET', '/activities', { auth: true, roles: ALL }, async (ctx) => {
    const where = [];
    const args = [];
    if (ctx.query.id) { where.push('a.id = ?'); args.push(intParam(ctx.query.id)); }
    if (ctx.query.from) { if (!isIsoDate(ctx.query.from)) throw new HttpError(400, 'INVALID_DATE'); where.push('a.activity_date >= ?'); args.push(ctx.query.from); }
    if (ctx.query.to) { if (!isIsoDate(ctx.query.to)) throw new HttpError(400, 'INVALID_DATE'); where.push('a.activity_date <= ?'); args.push(ctx.query.to); }
    if (scoped(ctx)) { where.push('a.created_by = ?'); args.push(ctx.user.id); }
    else if (ctx.query.userId) { where.push('a.created_by = ?'); args.push(intParam(ctx.query.userId)); }
    return (await ctx.db.prepare(`
      SELECT a.id, a.category_id, c.title AS category_title, a.activity_date, a.note, a.created_at,
             a.created_by AS user_id, u.first_name || ' ' || u.last_name AS user_name,
             COUNT(e.id) AS entries_count,
             COALESCE(SUM(e.raw_hours), 0) AS total_raw,
             COALESCE(SUM(e.final_hours), 0) AS total_final
      FROM activities a
      JOIN categories c ON c.id = a.category_id
      JOIN users u ON u.id = a.created_by
      LEFT JOIN activity_entries e ON e.activity_id = a.id
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      GROUP BY a.id
      ORDER BY a.activity_date DESC, a.id DESC`).all(...args));
  });

  const loadActivity = async (ctx, id) => {
    const a = (await ctx.db.prepare('SELECT * FROM activities WHERE id = ?').get(id));
    if (!a || (scoped(ctx) && a.created_by !== ctx.user.id)) throw new HttpError(404, 'NOT_FOUND');
    return a;
  };

  router.add('GET', '/activities/:id/entries', { auth: true, roles: ALL }, async (ctx) => {
    const a = await loadActivity(ctx, intParam(ctx.params.id));
    return (await ctx.db.prepare(`
      SELECT e.member_id, m.first_name, m.last_name, e.raw_hours, e.final_hours, r.version AS rule_version
      FROM activity_entries e
      JOIN members m ON m.id = e.member_id
      LEFT JOIN calculation_rules r ON r.id = e.applied_rule_id
      WHERE e.activity_id = ? ORDER BY e.id`).all(a.id));
  });

  router.add('POST', '/activities', { auth: true, roles: ALL }, async (ctx) => {
    const v = await readActivityBody(ctx, null);
    await enforceActivityRules(ctx, v, null);
    const id = (await ctx.db.prepare('INSERT INTO activities(created_by, category_id, activity_date, note, created_at) VALUES(?,?,?,?,?)')
      .run(ctx.user.id, v.categoryId, v.date, v.note, nowIso())).lastInsertRowid;
    try {
      await ctx.db.batch(await entryStatements(ctx.db, id, v.categoryId, v.date, v.entries));
    } catch (e) {
      await ctx.db.prepare('DELETE FROM activities WHERE id = ?').run(id).catch(() => {}); // nothing half-saved stays behind
      throw e;
    }
    await audit(ctx.db, ctx.user.id, 'activity.created', 'activity', id, {
      categoryId: v.categoryId, date: v.date, entries: v.entries.length, rawHours: round2(v.entries.reduce((s, e) => s + e.raw, 0)),
    });
    return [201, { id }];
  });

  router.add('PUT', '/activities/:id', { auth: true, roles: ALL }, async (ctx) => {
    await requireFlag(ctx, 'canEditActivities');
    const a = await loadActivity(ctx, intParam(ctx.params.id));
    const v = await readActivityBody(ctx, a.id);
    await enforceActivityRules(ctx, v, a);
    await ctx.db.batch([
      ctx.db.prepare('UPDATE activities SET category_id=?, activity_date=?, note=? WHERE id=?').bind(v.categoryId, v.date, v.note, a.id),
      ctx.db.prepare('DELETE FROM activity_entries WHERE activity_id = ?').bind(a.id),
      ...(await entryStatements(ctx.db, a.id, v.categoryId, v.date, v.entries)),
    ]);
    await audit(ctx.db, ctx.user.id, 'activity.updated', 'activity', a.id, {
      categoryId: v.categoryId, date: v.date, entries: v.entries.length, rawHours: round2(v.entries.reduce((s, e) => s + e.raw, 0)),
      previousDate: a.activity_date,
    });
    return { id: a.id };
  });

  router.add('DELETE', '/activities/:id', { auth: true, roles: ALL }, async (ctx) => {
    await requireFlag(ctx, 'canDeleteActivities');
    const a = await loadActivity(ctx, intParam(ctx.params.id));
    (await ctx.db.prepare('DELETE FROM activities WHERE id = ?').run(a.id));
    await audit(ctx.db, ctx.user.id, 'activity.deleted', 'activity', a.id, { categoryId: a.category_id, date: a.activity_date, ownerId: a.created_by });
    return { ok: true };
  });

  // ───────────── reports ─────────────
  router.add('GET', '/reports/rows', { auth: true, roles: ALL }, async (ctx) => {
    if (!isIsoDate(ctx.query.from) || !isIsoDate(ctx.query.to)) throw new HttpError(400, 'INVALID_DATE');
    const args = [ctx.query.from, ctx.query.to];
    let userFilter = '';
    if (scoped(ctx)) { userFilter = 'AND a.created_by = ?'; args.push(ctx.user.id); }
    else if (ctx.query.userId) { userFilter = 'AND a.created_by = ?'; args.push(intParam(ctx.query.userId)); }
    return (await ctx.db.prepare(`
      SELECT a.activity_date, a.id AS activity_id, a.created_at, a.created_by AS user_id,
             u.first_name || ' ' || u.last_name AS user_name, c.title AS category_title,
             m.id AS member_id, m.first_name, m.last_name,
             e.raw_hours, e.final_hours, r.version AS rule_version
      FROM activity_entries e
      JOIN activities a ON a.id = e.activity_id
      JOIN users u ON u.id = a.created_by
      JOIN categories c ON c.id = a.category_id
      JOIN members m ON m.id = e.member_id
      LEFT JOIN calculation_rules r ON r.id = e.applied_rule_id
      WHERE a.activity_date >= ? AND a.activity_date <= ? ${userFilter}
      ORDER BY a.activity_date, m.last_name, m.first_name`).all(...args));
  });
}

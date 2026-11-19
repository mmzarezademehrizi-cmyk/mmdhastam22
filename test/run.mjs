// End-to-end test: the real Worker code against an in-memory D1 stand-in.
import assert from 'node:assert/strict';
import worker from '../src/index.js';
import { Db, ensureSchema } from '../src/db.js';
import { initConfig } from '../src/config.js';
import { createOrUpdateOwner } from '../src/owner.js';
import { weekdayOf, tehranToday, addDaysIso } from '../src/schedule.js';
import { D1Shim } from './d1-shim.mjs';

const d1 = new D1Shim();
const env = {
  DB: d1,
  APP_JWT_SECRET: 'x'.repeat(40),
  SMS_PROVIDER: 'console',
  SETUP_KEY: 'setup-key-123456',
  PBKDF2_ITERATIONS: '1000', // fast tests (production default is 100000)
};
let logs = '';
const realLog = console.log;
console.log = (...a) => { logs += a.join(' ') + '\n'; };

initConfig(env);
const seedDb = new Db(d1);
await ensureSchema(seedDb);
await createOrUpdateOwner(seedDb, { phone: '09121111111', password: 'ownerpass1' });

let passed = 0;
async function call(method, p, body, token) {
  const res = await worker.fetch(new Request('https://api.test/appfaaliat' + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  }), env);
  return { status: res.status, body: await res.json() };
}
const ok = (name) => { passed++; realLog('  ok -', name); };

try {
  let r = await call('GET', '/auth/config');
  assert.equal(r.body.smsLoginEnabled, false); ok('sms login is off by default');

  r = await call('POST', '/auth/login-password', { phone: '09121111111', password: 'wrong-pass' });
  assert.equal(r.status, 401); ok('wrong password rejected');
  r = await call('POST', '/auth/login-password', { phone: '09121111111', password: 'ownerpass1' });
  assert.equal(r.status, 200); assert.equal(r.body.mustSetPassword, false);
  const owner = r.body.token; ok('owner login with phone + password');

  r = await call('POST', '/owner/users', {
    phone: '۰۹۱۲۲۲۲۲۲۲۲', firstName: 'علی', lastName: 'رضایی', role: 'user', password: 'temp12345', forcePasswordChange: true,
    profile: { father_name: 'حسن', national_id: '0499370899', city: 'تهران', birth_date: '1375-05-01', junk: 'x' },
    device: { device_brand: 'Samsung', device_model: 'A54', imei: '123456789012345' },
  }, owner);
  assert.equal(r.status, 201); assert.equal(r.body.profile.city, 'تهران'); assert.equal(r.body.profile.junk, undefined);
  assert.equal(r.body.device.device_model, 'A54'); assert.equal(r.body.phone, '+989122222222');
  const uid = r.body.id; ok('owner creates user with profile + phone info + password');

  r = await call('POST', '/owner/users', { phone: '09123333333', firstName: 'سارا', lastName: 'احمدی', profile: { national_id: '1234567890' } }, owner);
  assert.equal(r.status, 400); assert.equal(r.body.error, 'INVALID_NATIONAL_ID'); ok('invalid national id rejected');

  r = await call('POST', '/auth/login-password', { phone: '09122222222', password: 'temp12345' });
  assert.equal(r.status, 200); assert.equal(r.body.mustSetPassword, true); assert.equal(r.body.requiresCurrentPassword, true);
  let u1 = r.body.token; ok('user logs in with the password set by the owner');

  r = await call('GET', '/members', undefined, u1);
  assert.equal(r.status, 403); assert.equal(r.body.error, 'PASSWORD_SETUP_REQUIRED'); ok('blocked until the user creates his own password');
  r = await call('POST', '/auth/set-password', { newPassword: 'short' }, u1);
  assert.equal(r.status, 400); ok('password shorter than 8 rejected');
  r = await call('POST', '/auth/set-password', { newPassword: 'mynewpass1', currentPassword: 'nope' }, u1);
  assert.equal(r.status, 401); ok('wrong current password rejected');
  r = await call('POST', '/auth/set-password', { newPassword: 'mynewpass1', currentPassword: 'temp12345' }, u1);
  assert.equal(r.status, 200);
  r = await call('GET', '/members', undefined, u1);
  assert.equal(r.status, 200); ok('after setting his own password the user can work');

  // account without password + SMS switch
  r = await call('POST', '/owner/users', { phone: '09124444444', firstName: 'نرگس', lastName: 'کاظمی' }, owner);
  assert.equal(r.status, 201); assert.equal(r.body.hasPassword, false); const nid = r.body.id;
  r = await call('POST', '/auth/login-password', { phone: '09124444444', password: 'whatever12' });
  assert.equal(r.body.error, 'NO_PASSWORD_CONTACT_ADMIN'); ok('no password + sms off -> contact admin');
  r = await call('POST', '/auth/otp/request', { phone: '09124444444' });
  assert.equal(r.status, 403); assert.equal(r.body.error, 'SMS_LOGIN_DISABLED'); ok('otp refused while sms login is off');

  r = await call('PUT', '/owner/settings', { smsLoginEnabled: true }, u1);
  assert.equal(r.status, 403); ok('normal user cannot change settings');
  r = await call('PUT', '/owner/settings', { smsLoginEnabled: true }, owner);
  assert.equal(r.status, 200);
  r = await call('GET', '/auth/config'); assert.equal(r.body.smsLoginEnabled, true); ok('owner switches sms login on');

  r = await call('POST', '/auth/login-password', { phone: '09124444444', password: 'whatever12' });
  assert.equal(r.body.error, 'NO_PASSWORD_USE_OTP'); ok('no password + sms on -> use otp');
  r = await call('POST', '/auth/otp/request', { phone: '09124444444' });
  assert.equal(r.status, 200);
  const code = logs.match(/OTP for \+989124444444: (\d{6})/)?.[1];
  assert.ok(code, 'code printed by console provider');
  r = await call('POST', '/auth/otp/request', { phone: '09124444444' });
  assert.equal(r.status, 429); ok('otp cooldown');
  r = await call('POST', '/auth/otp/verify', { phone: '09124444444', code: code === '000000' ? '111111' : '000000' });
  assert.equal(r.status, 401);
  r = await call('POST', '/auth/otp/verify', { phone: '09124444444', code });
  assert.equal(r.status, 200); assert.equal(r.body.mustSetPassword, true); assert.equal(r.body.requiresCurrentPassword, false);
  const n1 = r.body.token; ok('otp login works and forces a new password');
  r = await call('POST', '/auth/set-password', { newPassword: 'narges1234' }, n1);
  assert.equal(r.status, 200); ok('fresh otp session sets password without the old one');
  r = await call('POST', '/auth/otp/verify', { phone: '09124444444', code });
  assert.equal(r.status, 401); ok('otp code cannot be reused');

  // lock after 5 wrong passwords
  for (let i = 0; i < 5; i++) await call('POST', '/auth/login-password', { phone: '09124444444', password: 'bad-bad-bad' });
  r = await call('POST', '/auth/login-password', { phone: '09124444444', password: 'narges1234' });
  assert.equal(r.status, 429); assert.equal(r.body.error, 'ACCOUNT_LOCKED'); ok('account locks after 5 wrong passwords');

  // owner sets a password for a user
  r = await call('POST', `/owner/users/${nid}/set-password`, { password: 'ownerset123', forceChange: false }, owner);
  assert.equal(r.status, 200);
  r = await call('POST', '/auth/login-password', { phone: '09124444444', password: 'ownerset123' });
  assert.equal(r.status, 200); assert.equal(r.body.mustSetPassword, false); ok('owner sets a user password (no forced change)');

  // data
  r = await call('POST', '/categories', { title: 'قرآن' }, u1); assert.equal(r.status, 403); ok('user cannot create categories');
  r = await call('POST', '/categories', { title: 'قرآن' }, owner); assert.equal(r.status, 201); const cid = r.body.id;
  r = await call('POST', `/categories/${cid}/rules`, { operation: 'add_then_multiply', addHours: 1, multiplier: 2, effectiveFrom: '2020-01-01' }, owner);
  assert.equal(r.status, 201); ok('owner creates category + versioned rule');
  r = await call('POST', '/members', { firstName: 'محمد', lastName: 'کریمی', nationalId: '0499370899' }, u1); assert.equal(r.status, 201); const mid = r.body.id;
  r = await call('POST', '/members', { firstName: 'تکراری', lastName: 'تست', nationalId: '0499370899' }, u1); assert.equal(r.status, 409); ok('duplicate national id rejected');
  r = await call('POST', '/members/bulk', { members: [{ firstName: 'a', lastName: 'b' }, { firstName: '', lastName: 'x' }] }, u1);
  assert.deepEqual([r.body.added, r.body.skipped], [1, 1]); ok('bulk members');
  r = await call('POST', '/activities', { categoryId: cid, date: '2026-11-01', note: 't', entries: [{ memberId: mid, rawHours: 2 }] }, u1);
  assert.equal(r.status, 201); const aid = r.body.id;
  r = await call('GET', `/activities/${aid}/entries`, undefined, u1);
  assert.equal(r.body[0].final_hours, 6); assert.equal(r.body[0].rule_version, 1); ok('rule (2+1)*2 = 6 applied and remembered');
  r = await call('GET', '/activities?from=2026-11-01&to=2026-11-30', undefined, u1);
  assert.equal(r.body[0].total_final, 6);
  r = await call('GET', '/reports/rows?from=2026-11-01&to=2026-11-30', undefined, u1); assert.equal(r.body.length, 1);
  r = await call('GET', '/reports/rows?from=2026-11-01&to=2026-11-30', undefined, n1 /* revoked? */);
  r = await call('DELETE', `/members/${mid}`, undefined, u1); assert.equal(r.status, 409); ok('member used in an activity cannot be deleted');

  // role "user" only sees his own data; owner sees everything
  r = await call('POST', '/auth/login-password', { phone: '09124444444', password: 'ownerset123' }); const n2 = r.body.token;
  r = await call('GET', '/activities', undefined, n2); assert.equal(r.body.length, 0);
  r = await call('GET', '/members', undefined, n2); assert.equal(r.body.length, 0);
  r = await call('GET', `/activities/${aid}/entries`, undefined, n2); assert.equal(r.status, 404);
  r = await call('GET', '/activities', undefined, owner); assert.equal(r.body.length, 1); ok('users see only their own data, owner sees all');

  // owner tools
  r = await call('GET', '/owner/users', undefined, owner); assert.ok(r.body.length >= 3 && r.body.some((x) => x.online)); ok('owner lists users with online status');
  r = await call('GET', `/owner/users/${uid}`, undefined, owner); assert.equal(r.body.device.imei, '123456789012345');
  r = await call('PUT', `/owner/users/${uid}`, { isActive: false }, owner); assert.equal(r.status, 200);
  r = await call('GET', '/members', undefined, u1); assert.equal(r.status, 401); ok('disabling a user kills his sessions');
  r = await call('POST', '/auth/login-password', { phone: '09122222222', password: 'mynewpass1' }); assert.equal(r.status, 403);
  r = await call('POST', `/owner/users/${nid}/reset-password`, undefined, owner); assert.equal(r.status, 200);
  r = await call('POST', '/auth/login-password', { phone: '09124444444', password: 'ownerset123' }); assert.equal(r.body.error, 'NO_PASSWORD_USE_OTP'); ok('reset password works');


  // ───── weekly schedule, user rules, owner oversight ─────
  r = await call('POST', '/owner/users', { phone: '09125555555', firstName: 'رضا', lastName: 'نوری', password: 'rezapass12', forcePasswordChange: false }, owner);
  assert.equal(r.status, 201); const rid = r.body.id;
  r = await call('POST', '/auth/login-password', { phone: '09125555555', password: 'rezapass12' });
  assert.equal(r.status, 200); const ru = r.body.token;
  const today = tehranToday();
  const dateWithWeekday = (wd, from = today) => { let d = from; while (weekdayOf(d) !== wd) d = addDaysIso(d, -1); return d; };

  r = await call('POST', '/categories', { title: 'کلاس', dayMode: 'custom', days: [1, 4] }, owner); assert.equal(r.status, 201); const sid = r.body.id;
  r = await call('POST', '/categories', { title: 'فرد', dayMode: 'odd' }, owner); const oddId = r.body.id;
  r = await call('POST', '/categories', { title: 'زوج', dayMode: 'even' }, owner); const evenId = r.body.id;
  r = await call('POST', '/categories', { title: 'بد', dayMode: 'custom', days: [] }, owner); assert.equal(r.body.error, 'INVALID_DAYS');
  r = await call('POST', '/categories', { title: 'بد', dayMode: 'weekly' }, owner); assert.equal(r.body.error, 'INVALID_DAY_MODE');
  r = await call('GET', '/categories', undefined, ru);
  const byId = Object.fromEntries(r.body.map((c) => [c.id, c]));
  assert.deepEqual(byId[sid].days, [1, 4]); assert.equal(byId[sid].day_mode, 'custom');
  assert.deepEqual(byId[oddId].days, [0, 2, 4, 6]); assert.deepEqual(byId[evenId].days, [1, 3, 5]);
  assert.deepEqual(byId[cid].days, [0, 1, 2, 3, 4, 5, 6]); ok('category weekdays: custom / odd / even / every');

  r = await call('POST', '/members', { firstName: 'عضو', lastName: 'یک' }, ru); const m1 = r.body.id;
  const wed = dateWithWeekday(4); const mon = dateWithWeekday(2);
  r = await call('POST', '/activities', { categoryId: sid, date: mon, entries: [{ memberId: m1, rawHours: 1 }] }, ru);
  assert.equal(r.status, 400); assert.equal(r.body.error, 'DAY_NOT_ALLOWED'); assert.deepEqual(r.body.allowedDays, [1, 4]);
  r = await call('POST', '/activities', { categoryId: sid, date: wed, entries: [{ memberId: m1, rawHours: 1.5 }] }, ru);
  assert.equal(r.status, 201); const a1 = r.body.id; ok('activity only on the weekdays of the category');
  r = await call('POST', '/activities', { categoryId: sid, date: mon, entries: [{ memberId: m1, rawHours: 1 }] }, owner);
  assert.equal(r.status, 201); ok('owner / admin may log on any weekday');
  r = await call('PUT', `/categories/${sid}`, { dayMode: 'every' }, owner); assert.equal(r.status, 200);
  r = await call('PUT', `/activities/${a1}`, { categoryId: sid, date: wed, entries: [{ memberId: m1, rawHours: 2 }] }, ru);
  assert.equal(r.status, 200); ok('changing the schedule keeps old activities editable');
  r = await call('PUT', `/categories/${sid}`, { dayMode: 'custom', days: [1, 4] }, owner);
  r = await call('PUT', `/activities/${a1}`, { categoryId: sid, date: wed, entries: [{ memberId: m1, rawHours: 2.5 }] }, ru);
  assert.equal(r.status, 200); ok('editing hours on an unchanged day works');

  r = await call('GET', `/reports/rows?from=${wed}&to=${wed}`, undefined, ru);
  assert.equal(r.body.length, 1); assert.equal(r.body[0].activity_date, wed); assert.ok(r.body[0].created_at); assert.equal(r.body[0].user_name, 'رضا نوری'); ok('report rows carry the exact date + registration time');
  r = await call('GET', `/reports/rows?from=${wed}&to=${wed}&userId=${rid}`, undefined, owner); assert.equal(r.body.length, 1);
  r = await call('GET', `/reports/rows?from=${wed}&to=${wed}&userId=${uid}`, undefined, owner); assert.equal(r.body.length, 0);
  r = await call('GET', `/activities?userId=${rid}`, undefined, owner); assert.equal(r.body.length, 1); assert.equal(r.body[0].user_name, 'رضا نوری'); ok('owner filters reports / activities by user');

  // user rules
  r = await call('GET', '/me/policy', undefined, ru); assert.equal(r.body.limited, true); assert.equal(r.body.policy.canEditActivities, true);
  r = await call('GET', '/me/policy', undefined, owner); assert.equal(r.body.limited, false);
  r = await call('PUT', `/owner/users/${rid}/policy`, { policy: { allowFutureDates: false, maxBackdateDays: 3, maxHoursPerEntry: 5, canDeleteActivities: false, canEditActivities: false, canManageMembers: false } }, owner);
  assert.equal(r.status, 200); assert.equal(r.body.policy.maxBackdateDays, 3);
  r = await call('PUT', `/owner/users/${rid}/policy`, { policy: { canEditActivities: 'yes', maxBackdateDays: -5 } }, u1); assert.equal(r.status, 401);
  const anyDay = (n) => addDaysIso(today, n);
  r = await call('POST', '/activities', { categoryId: cid, date: anyDay(30), entries: [{ memberId: m1, rawHours: 1 }] }, ru); assert.equal(r.body.error, 'FUTURE_DATE_NOT_ALLOWED');
  r = await call('POST', '/activities', { categoryId: cid, date: anyDay(-10), entries: [{ memberId: m1, rawHours: 1 }] }, ru); assert.equal(r.body.error, 'DATE_TOO_OLD');
  r = await call('POST', '/activities', { categoryId: cid, date: today, entries: [{ memberId: m1, rawHours: 6 }] }, ru); assert.equal(r.body.error, 'HOURS_LIMIT_EXCEEDED');
  r = await call('POST', '/activities', { categoryId: cid, date: today, entries: [{ memberId: m1, rawHours: 4 }] }, ru); assert.equal(r.status, 201); const a2 = r.body.id;
  r = await call('PUT', `/activities/${a2}`, { categoryId: cid, date: today, entries: [{ memberId: m1, rawHours: 3 }] }, ru); assert.equal(r.body.error, 'NOT_ALLOWED_BY_OWNER');
  r = await call('DELETE', `/activities/${a2}`, undefined, ru); assert.equal(r.body.error, 'NOT_ALLOWED_BY_OWNER');
  r = await call('POST', '/members', { firstName: 'x', lastName: 'y' }, ru); assert.equal(r.body.error, 'NOT_ALLOWED_BY_OWNER'); ok('owner limits: dates, hours, edit, delete, members');
  r = await call('PUT', `/owner/users/${rid}/policy`, { policy: { allowedCategoryIds: [oddId] } }, owner);
  r = await call('GET', '/categories', undefined, ru); assert.deepEqual(r.body.map((c) => c.id), [oddId]);
  r = await call('POST', '/activities', { categoryId: cid, date: today, entries: [{ memberId: m1, rawHours: 1 }] }, ru); assert.equal(r.body.error, 'CATEGORY_NOT_ALLOWED'); ok('owner limits the categories of a user');

  // oversight
  r = await call('GET', `/owner/users/${rid}`, undefined, owner); assert.equal(r.body.policy.allowedCategoryIds[0], oddId);
  r = await call('GET', `/owner/users/${rid}/overview`, undefined, owner);
  assert.equal(r.body.online, true); assert.ok(r.body.membersTotal >= 1); assert.ok(r.body.last30Days.activities >= 1); assert.ok(r.body.lastLoginAt); assert.ok(r.body.activeSessions >= 1); ok('owner sees an overview of one user');
  r = await call('GET', `/owner/activity-log?userId=${rid}&limit=20`, undefined, owner);
  const actions = r.body.map((x) => x.action);
  assert.ok(actions.includes('auth.login') && actions.includes('activity.created') && actions.includes('user.policy_changed')); ok('activity log lists logins, activities, rule changes');
  r = await call('GET', '/owner/dashboard', undefined, owner);
  assert.equal(r.body.today, today); assert.ok(r.body.users.total >= 4); assert.ok(r.body.todayStats.activities >= 1); assert.ok(Array.isArray(r.body.inactiveUsers)); ok('owner dashboard');
  r = await call('GET', '/owner/users', undefined, owner); const rz = r.body.find((x) => x.id === rid); assert.ok(rz.activities7d >= 1); assert.ok(rz.lastActivityDate);
  r = await call('POST', `/owner/users/${rid}/logout-all`, undefined, owner); assert.equal(r.status, 200); assert.ok(r.body.revoked >= 1);
  r = await call('GET', '/members', undefined, ru); assert.equal(r.status, 401); ok('owner signs a user out of every device');
  r = await call('GET', '/owner/dashboard', undefined, ru); assert.equal(r.status, 401);


  // ───── Workers-specific: base path, setup, configuration, D1 limits ─────
  const raw = (path, init, e = env) => worker.fetch(new Request('https://api.test' + path, init), e);
  let rr = await raw('/appfaaliat/'); let jj = await rr.json(); assert.equal(jj.ok, true); assert.equal(jj.configured, true);
  rr = await raw('/appfaaliat'); assert.equal(rr.status, 200);
  rr = await raw('/health'); assert.equal(rr.status, 404);
  rr = await raw('/elsewhere/health'); assert.equal(rr.status, 404); ok('API lives under /appfaaliat only');

  r = await call('GET', '/setup/status'); assert.equal(r.body.hasOwner, true); assert.equal(r.body.setupEnabled, true);
  r = await call('POST', '/setup/owner', { setupKey: 'wrong-key-123456', phone: '09127777777', password: 'newowner123' }); assert.equal(r.body.error, 'WRONG_SETUP_KEY');
  r = await call('POST', '/setup/owner', { setupKey: 'setup-key-123456', phone: '09127777777', password: 'short' }); assert.equal(r.body.error, 'INVALID_PASSWORD');
  r = await call('POST', '/setup/owner', { setupKey: 'setup-key-123456', phone: '09127777777', password: 'newowner123', firstName: 'مدیر' }); assert.equal(r.status, 201);
  r = await call('POST', '/auth/login-password', { phone: '09127777777', password: 'newowner123' }); assert.equal(r.status, 200); assert.equal(r.body.user.role, 'owner');
  r = await call('POST', '/setup/owner', { setupKey: 'setup-key-123456', phone: '09127777777', password: 'changed12345' }); assert.equal(r.status, 200); assert.equal(r.body.created, false);
  r = await call('POST', '/auth/login-password', { phone: '09127777777', password: 'changed12345' }); assert.equal(r.status, 200); ok('first-time owner setup + password reset with SETUP_KEY');
  rr = await raw('/appfaaliat/setup/owner', { method: 'POST', body: JSON.stringify({ setupKey: 'x', phone: '09120000000', password: 'password123' }) }, { ...env, SETUP_KEY: '' });
  assert.equal((await rr.json()).error, 'SETUP_DISABLED'); ok('setup endpoint is off without SETUP_KEY');

  rr = await raw('/appfaaliat/auth/config', {}, { ...env, DB: undefined }); assert.equal(rr.status, 503); assert.equal((await rr.json()).error, 'DATABASE_NOT_CONNECTED');
  rr = await raw('/appfaaliat/auth/config', {}, { ...env, APP_JWT_SECRET: 'short' }); assert.equal(rr.status, 503); assert.equal((await rr.json()).error, 'SERVER_NOT_CONFIGURED');
  r = await call('GET', '/auth/config'); assert.equal(r.status, 200); ok('clear errors when the D1 binding or secret is missing');

  const many = Array.from({ length: 45 }, (_, i) => ({ firstName: 'عضو', lastName: `n${i}` }));
  many.push({ firstName: '', lastName: '' }, { firstName: 'x', lastName: 'y', nationalId: '123' });
  r = await call('POST', '/members/bulk', { members: many }, owner); assert.equal(r.body.added, 45); assert.equal(r.body.skipped, 2);
  r = await call('GET', '/members', undefined, owner); const ids = r.body.filter((m) => m.last_name.startsWith('n')).map((m) => m.id); assert.equal(ids.length, 45); ok('bulk insert of 45 members (D1 variable limit respected)');
  r = await call('POST', '/activities', { categoryId: cid, date: today, entries: ids.slice(0, 40).map((id) => ({ memberId: id, rawHours: 1.5 })) }, owner);
  assert.equal(r.status, 201); const bigId = r.body.id;
  r = await call('GET', `/activities/${bigId}/entries`, undefined, owner); assert.equal(r.body.length, 40);
  r = await call('PUT', `/activities/${bigId}`, { categoryId: cid, date: today, entries: ids.slice(0, 20).map((id) => ({ memberId: id, rawHours: 2 })) }, owner);
  assert.equal(r.status, 200);
  r = await call('GET', `/activities/${bigId}/entries`, undefined, owner); assert.equal(r.body.length, 20); assert.equal(r.body[0].raw_hours, 2); ok('activity with 40 then 20 hour rows (atomic batches)');
  r = await call('DELETE', `/activities/${bigId}`, undefined, owner); assert.equal(r.status, 200);
  r = await call('GET', `/activities/${bigId}/entries`, undefined, owner); assert.equal(r.status, 404);


  // ───── regression: every response shape the apps parse ─────
  r = await call('GET', `/categories/${cid}/rule-at?date=${today}`, undefined, owner);
  assert.equal(r.status, 200); assert.ok(r.body.rule && r.body.rule.version >= 1 && typeof r.body.rule.id === 'number' && typeof r.body.rule.category_id === 'number');
  assert.equal(typeof r.body.rule.add_hours, 'number'); assert.equal(typeof r.body.rule.multiplier, 'number'); assert.ok(r.body.rule.effective_from);
  r = await call('GET', `/categories/${sid}/rule-at?date=${today}`, undefined, owner); assert.equal(r.status, 200); assert.equal(r.body.rule, null);
  r = await call('GET', `/categories/${cid}/rules`, undefined, owner); assert.ok(r.body.length >= 1 && typeof r.body[0].id === 'number');
  r = await call('GET', `/categories/${cid}/usage`, undefined, owner); assert.equal(typeof r.body.count, 'number');
  r = await call('GET', '/members/' + ids[0] + '/usage', undefined, owner); assert.equal(typeof r.body.count, 'number');
  r = await call('GET', '/categories', undefined, owner);
  for (const c of r.body) { assert.equal(typeof c.id, 'number'); assert.equal(typeof c.title, 'string'); assert.ok([0, 1].includes(c.is_active)); assert.equal(typeof c.sort_order, 'number'); assert.ok(Array.isArray(c.days)); }
  r = await call('GET', '/auth/me', undefined, owner); assert.equal(r.status, 200); assert.ok(r.body.user.id);
  r = await call('GET', '/owner/settings', undefined, owner); assert.equal(r.status, 200);
  r = await call('GET', '/owner/info-fields', undefined, owner); assert.equal(r.status, 200);
  ok('rule-at / rules / usage / list shapes the apps parse');

  realLog(`\nALL ${passed} CHECKS PASSED`);
} catch (e) {
  realLog('\nTEST FAILED:', e);
  realLog('--- log ---\n' + logs);
  process.exitCode = 1;
} finally {
  console.log = realLog;
}

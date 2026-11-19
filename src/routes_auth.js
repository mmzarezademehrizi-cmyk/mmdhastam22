import { cfg } from './config.js';
import { getSetting, audit, cleanup } from './db.js';
import { createSession, issueToken, needsCurrentPassword, userPayload } from './auth.js';
import { sendOtp } from './sms.js';
import {
  HttpError, hashPassword, verifyPassword, dummyVerify, normalizePhone, nowIso, addMs,
  hmacHex, randomInt, fromHex, timingSafeEqual,
} from './util.js';

const MAX_FAILED = 5;
const LOCK_MS = 15 * 60 * 1000;
const OTP_TTL_MS = 5 * 60 * 1000;
const OTP_COOLDOWN_S = 60;
const OTP_MAX_ATTEMPTS = 5;
const ALL = ['owner', 'admin', 'operator', 'user'];

export const smsEnabled = async (db) => (await getSetting(db, 'sms_login_enabled', '0')) === '1';

const otpHash = (phone, code) => hmacHex(cfg.jwtSecret, `${phone}:${code}`);

function str(v, name, min = 1, max = 200) {
  if (typeof v !== 'string' || v.length < min || v.length > max) throw new HttpError(400, 'INVALID_BODY', { field: name });
  return v;
}

export function registerAuthRoutes(router, app) {
  const { limiter } = app;

  router.add('GET', '/', {}, () => ({ ok: true, service: 'activity-system-api' }));
  router.add('GET', '/health', {}, async (ctx) => {
    (await ctx.db.prepare('SELECT 1').get());
    return { ok: true };
  });

  // Public: lets the app know whether to show the "login with SMS" button.
  router.add('GET', '/auth/config', {}, async (ctx) => ({ smsLoginEnabled: await smsEnabled(ctx.db) }));

  // ───── phone + password ─────
  router.add('POST', '/auth/login-password', {}, async (ctx) => {
    limiter.check(`login:ip:${ctx.ip}`, 20, 60_000);
    const phone = normalizePhone(str(ctx.body.phone, 'phone', 5, 30));
    const password = str(ctx.body.password, 'password', 1, cfg.passwordMax);
    if (!phone) throw new HttpError(400, 'INVALID_PHONE');
    limiter.check(`login:phone:${phone}`, 15, 60_000);
    const db = ctx.db;

    const user = (await db.prepare('SELECT * FROM users WHERE phone = ?').get(phone));
    if (!user) {
      await dummyVerify(password);
      throw new HttpError(401, 'INVALID_CREDENTIALS');
    }
    if (user.locked_until && Date.parse(user.locked_until) > Date.now()) {
      throw new HttpError(429, 'ACCOUNT_LOCKED', { retryAfterSeconds: Math.ceil((Date.parse(user.locked_until) - Date.now()) / 1000) });
    }
    if (!user.is_active) throw new HttpError(403, 'USER_DISABLED');
    if (!user.password_hash) {
      throw new HttpError(409, (await smsEnabled(db)) ? 'NO_PASSWORD_USE_OTP' : 'NO_PASSWORD_CONTACT_ADMIN');
    }

    const ok = await verifyPassword(password, user.password_hash);
    if (!ok) {
      const failed = user.failed_login_count + 1;
      const lock = failed >= MAX_FAILED;
      (await db.prepare('UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?')
        .run(lock ? 0 : failed, lock ? addMs(LOCK_MS) : null, user.id));
      await audit(db, user.id, lock ? 'auth.locked' : 'auth.login_failed', 'user', user.id, { ip: ctx.ip, attempts: failed });
      throw new HttpError(401, 'INVALID_CREDENTIALS', { attemptsLeft: lock ? 0 : MAX_FAILED - failed });
    }
    if (user.failed_login_count || user.locked_until) {
      (await db.prepare('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ?').run(user.id));
    }
    const { sessionId, expiresAt } = await createSession(db, user.id, 'password');
    await audit(db, user.id, 'auth.login', 'user', user.id, { method: 'password', ip: ctx.ip });
    if (Math.random() < 0.02) await cleanup(db).catch(() => {});
    return {
      token: await issueToken(user, sessionId), expiresAt,
      mustSetPassword: user.must_set_password === 1,
      requiresCurrentPassword: user.must_set_password === 1,
      user: userPayload(user),
    };
  });

  // ───── SMS one-time code (can be switched off by the owner) ─────
  router.add('POST', '/auth/otp/request', {}, async (ctx) => {
    limiter.check(`otp:ip:${ctx.ip}`, 10, 60_000);
    const db = ctx.db;
    if (!(await smsEnabled(db))) throw new HttpError(403, 'SMS_LOGIN_DISABLED');
    const phone = normalizePhone(str(ctx.body.phone, 'phone', 5, 30));
    if (!phone) throw new HttpError(400, 'INVALID_PHONE');

    const last = (await db.prepare('SELECT created_at FROM otp_codes WHERE phone = ? ORDER BY id DESC LIMIT 1').get(phone));
    if (last) {
      const wait = OTP_COOLDOWN_S - Math.floor((Date.now() - Date.parse(last.created_at)) / 1000);
      if (wait > 0) throw new HttpError(429, 'OTP_COOLDOWN', { retryAfterSeconds: wait });
    }
    const hourAgo = new Date(Date.now() - 3600_000).toISOString();
    const count = (await db.prepare('SELECT COUNT(*) AS c FROM otp_codes WHERE phone = ? AND created_at > ?').get(phone, hourAgo)).c;
    if (count >= 5) throw new HttpError(429, 'RATE_LIMITED', { retryAfterSeconds: 600 });

    // Same answer whether or not the phone exists (no user enumeration).
    const user = (await db.prepare('SELECT id, is_active FROM users WHERE phone = ?').get(phone));
    const reply = { ok: true, resendAfterSeconds: OTP_COOLDOWN_S };
    if (!user || !user.is_active) {
      (await db.prepare('INSERT INTO otp_codes(phone, code_hash, expires_at, created_at, used_at) VALUES(?,?,?,?,?)')
        .run(phone, 'none', nowIso(), nowIso(), nowIso())); // keeps the cooldown identical
      return reply;
    }

    const code = String(randomInt(10 ** cfg.smsOtpLength)).padStart(cfg.smsOtpLength, '0');
    const id = (await db.prepare('INSERT INTO otp_codes(phone, code_hash, expires_at, created_at) VALUES(?,?,?,?)')
      .run(phone, await otpHash(phone, code), addMs(OTP_TTL_MS), nowIso())).lastInsertRowid;
    try {
      await sendOtp(phone, code);
    } catch (e) {
      console.error('SMS send failed:', e.message);
      (await db.prepare('DELETE FROM otp_codes WHERE id = ?').run(id));
      throw new HttpError(502, 'OTP_SEND_FAILED');
    }
    return reply;
  });

  router.add('POST', '/auth/otp/verify', {}, async (ctx) => {
    limiter.check(`otpv:ip:${ctx.ip}`, 20, 60_000);
    const db = ctx.db;
    if (!(await smsEnabled(db))) throw new HttpError(403, 'SMS_LOGIN_DISABLED');
    const phone = normalizePhone(str(ctx.body.phone, 'phone', 5, 30));
    const code = str(ctx.body.code, 'code', 3, 12).replace(/\s/g, '');
    if (!phone) throw new HttpError(400, 'INVALID_PHONE');

    const row = (await db.prepare('SELECT * FROM otp_codes WHERE phone = ? AND used_at IS NULL ORDER BY id DESC LIMIT 1').get(phone));
    if (!row || Date.parse(row.expires_at) <= Date.now() || row.attempts >= OTP_MAX_ATTEMPTS) {
      throw new HttpError(401, 'INVALID_OTP');
    }
    const given = fromHex(await otpHash(phone, code));
    const expected = fromHex(row.code_hash);
    if (!timingSafeEqual(given, expected)) {
      (await db.prepare('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?').run(row.id));
      throw new HttpError(401, 'INVALID_OTP');
    }
    (await db.prepare('UPDATE otp_codes SET used_at = ? WHERE id = ?').run(nowIso(), row.id));

    const user = (await db.prepare('SELECT * FROM users WHERE phone = ?').get(phone));
    if (!user || !user.is_active) throw new HttpError(403, 'USER_DISABLED');

    // OTP login = "no password / forgot password": always force a new password.
    (await db.prepare('UPDATE users SET must_set_password = 1, failed_login_count = 0, locked_until = NULL WHERE id = ?').run(user.id));
    const { sessionId, expiresAt } = await createSession(db, user.id, 'otp');
    await audit(db, user.id, 'auth.login', 'user', user.id, { method: 'otp', ip: ctx.ip });
    return {
      token: await issueToken(user, sessionId), expiresAt,
      mustSetPassword: true, requiresCurrentPassword: false,
      user: userPayload(user),
    };
  });

  // ───── create / change own password ─────
  router.add('POST', '/auth/set-password', { auth: true, allowPending: true }, async (ctx) => {
    limiter.check(`setpw:${ctx.user.id}`, 10, 60_000);
    const newPassword = ctx.body.newPassword;
    if (typeof newPassword !== 'string' || newPassword.length < cfg.passwordMin || newPassword.length > cfg.passwordMax) {
      throw new HttpError(400, 'INVALID_PASSWORD', { minLength: cfg.passwordMin });
    }
    const db = ctx.db;
    const user = (await db.prepare('SELECT id, password_hash FROM users WHERE id = ?').get(ctx.user.id));
    if (user.password_hash && needsCurrentPassword(ctx.user)) {
      const cur = typeof ctx.body.currentPassword === 'string' ? ctx.body.currentPassword : '';
      if (!cur || !(await verifyPassword(cur, user.password_hash))) throw new HttpError(401, 'WRONG_CURRENT_PASSWORD');
    }
    (await db.prepare('UPDATE users SET password_hash = ?, must_set_password = 0, password_updated_at = ?, failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?')
      .run(await hashPassword(newPassword), nowIso(), nowIso(), user.id));
    (await db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id != ? AND revoked_at IS NULL')
      .run(nowIso(), user.id, ctx.user.sessionId));
    await audit(db, user.id, 'auth.password_set', 'user', user.id);
    return { ok: true };
  });

  router.add('GET', '/auth/me', { auth: true, allowPending: true }, async (ctx) => {
    const u = (await ctx.db.prepare('SELECT id, first_name, last_name, role FROM users WHERE id = ?').get(ctx.user.id));
    return {
      user: userPayload(u),
      mustSetPassword: ctx.user.mustSetPassword,
      requiresCurrentPassword: needsCurrentPassword(ctx.user),
    };
  });

  router.add('POST', '/auth/logout', { auth: true, allowPending: true }, async (ctx) => {
    (await ctx.db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(nowIso(), ctx.user.sessionId));
    return { ok: true };
  });

  router.add('POST', '/presence/heartbeat', { auth: true, roles: ALL }, async (ctx) => {
    const now = nowIso();
    (await ctx.db.prepare('INSERT INTO presence(user_id, last_seen_at) VALUES(?, ?) ON CONFLICT(user_id) DO UPDATE SET last_seen_at = excluded.last_seen_at')
      .run(ctx.user.id, now));
    return { ok: true, lastSeenAt: now };
  });
}

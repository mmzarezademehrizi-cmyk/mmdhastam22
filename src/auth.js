import { cfg } from './config.js';
import { HttpError, signJwt, verifyJwt, nowIso, addMs } from './util.js';

const OTP_SESSION_FRESH_MS = 15 * 60 * 1000;

export function userPayload(u) {
  return { id: u.id, firstName: u.first_name, lastName: u.last_name, role: u.role };
}

export function issueToken(user, sessionId) {
  return signJwt({ sub: String(user.id), role: user.role, sid: sessionId }, cfg.jwtSecret, cfg.sessionDays * 86400);
}

export async function createSession(db, userId, method) {
  const id = crypto.randomUUID();
  const expiresAt = addMs(cfg.sessionDays * 86400 * 1000);
  const now = nowIso();
  await db.batch([
    db.prepare('INSERT INTO sessions(id, user_id, created_at, expires_at, auth_method) VALUES(?,?,?,?,?)').bind(id, userId, now, expiresAt, method),
    db.prepare('INSERT INTO presence(user_id, last_seen_at) VALUES(?, ?) ON CONFLICT(user_id) DO UPDATE SET last_seen_at = excluded.last_seen_at').bind(userId, now),
  ]);
  return { sessionId: id, expiresAt };
}

/** Existing password must be re-entered unless this is a fresh OTP session. */
export function needsCurrentPassword(auth) {
  if (!auth.hasPassword) return false;
  const fresh = auth.authMethod === 'otp' && Date.now() - Date.parse(auth.sessionCreatedAt) <= OTP_SESSION_FRESH_MS;
  return !fresh;
}

/**
 * Checks the Bearer token + session + user. By default a user who must still create a
 * password is blocked (403 PASSWORD_SETUP_REQUIRED) unless opts.allowPending.
 */
export async function authenticate(ctx, opts) {
  const header = ctx.req.headers.get('authorization') || '';
  if (!header.startsWith('Bearer ')) throw new HttpError(401, 'UNAUTHORIZED');
  const payload = await verifyJwt(header.slice(7), cfg.jwtSecret);
  if (!payload || !payload.sid || !payload.sub) throw new HttpError(401, 'UNAUTHORIZED');

  const row = await ctx.db.prepare(`
    SELECT s.id AS sid, s.created_at AS session_created_at, s.expires_at, s.revoked_at, s.auth_method,
           u.id, u.role, u.is_active, u.must_set_password, u.password_hash, u.first_name, u.last_name
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.id = ? AND u.id = ?`).get(payload.sid, Number(payload.sub));
  if (!row || row.revoked_at || Date.parse(row.expires_at) <= Date.now()) throw new HttpError(401, 'SESSION_EXPIRED');
  if (!row.is_active) throw new HttpError(403, 'USER_DISABLED');

  const auth = {
    id: row.id, role: row.role, sessionId: row.sid,
    firstName: row.first_name, lastName: row.last_name,
    authMethod: row.auth_method, sessionCreatedAt: row.session_created_at,
    hasPassword: Boolean(row.password_hash),
    mustSetPassword: row.must_set_password === 1 || !row.password_hash,
  };
  if (opts.roles && !opts.roles.includes(auth.role)) throw new HttpError(403, 'FORBIDDEN');
  if (auth.mustSetPassword && !opts.allowPending) throw new HttpError(403, 'PASSWORD_SETUP_REQUIRED');
  return auth;
}

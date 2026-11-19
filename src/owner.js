import { cfg } from './config.js';
import { hashPassword, normalizePhone, nowIso } from './util.js';

/** Creates the first owner, or resets the password of an existing account. */
export async function createOrUpdateOwner(db, { phone, password, first = 'مالک', last = 'سامانه' }) {
  const p = normalizePhone(phone);
  if (!p) throw new Error('INVALID_PHONE');
  if (typeof password !== 'string' || password.length < cfg.passwordMin || password.length > cfg.passwordMax) {
    throw new Error('INVALID_PASSWORD');
  }
  const hash = await hashPassword(password);
  const now = nowIso();
  const cur = await db.prepare('SELECT id FROM users WHERE phone = ?').get(p);
  if (cur) {
    await db.batch([
      db.prepare("UPDATE users SET role='owner', is_active=1, password_hash=?, must_set_password=0, password_updated_at=?, failed_login_count=0, locked_until=NULL, updated_at=? WHERE id=?")
        .bind(hash, now, now, cur.id),
      db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(now, cur.id),
    ]);
    return { id: cur.id, phone: p, created: false };
  }
  const r = await db.prepare(`INSERT INTO users(phone, first_name, last_name, role, is_active, password_hash, must_set_password,
      password_updated_at, created_at, updated_at) VALUES(?,?,?,'owner',1,?,0,?,?,?)`).run(p, first, last, hash, now, now, now);
  return { id: r.lastInsertRowid, phone: p, created: true };
}

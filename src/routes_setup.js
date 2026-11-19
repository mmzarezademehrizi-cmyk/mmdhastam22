import { cfg } from './config.js';
import { audit } from './db.js';
import { createOrUpdateOwner } from './owner.js';
import { HttpError, cleanText, sha256, timingSafeEqual } from './util.js';

/**
 * First-time setup without a terminal:
 *   POST /setup/owner  { "setupKey": "...", "phone": "09...", "password": "...", "firstName"?, "lastName"? }
 * Needs the secret SETUP_KEY (>= 12 characters). With the same key you can also reset the owner's password later.
 * Remove the SETUP_KEY secret when you do not need it any more: the endpoint is then disabled.
 */
export function registerSetupRoutes(router, app) {
  router.add('GET', '/setup/status', {}, async (ctx) => {
    const n = (await ctx.db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'owner'").get()).c;
    return { hasOwner: n > 0, setupEnabled: cfg.setupKey.length >= 12 };
  });

  router.add('POST', '/setup/owner', {}, async (ctx) => {
    app.limiter.check(`setup:${ctx.ip}`, 10, 60_000);
    if (cfg.setupKey.length < 12) throw new HttpError(403, 'SETUP_DISABLED');
    const given = await sha256(String(ctx.body.setupKey ?? ''));
    const wanted = await sha256(cfg.setupKey);
    if (!timingSafeEqual(given, wanted)) throw new HttpError(403, 'WRONG_SETUP_KEY');
    try {
      const r = await createOrUpdateOwner(ctx.db, {
        phone: ctx.body.phone,
        password: ctx.body.password,
        first: cleanText(ctx.body.firstName, 80) || undefined,
        last: cleanText(ctx.body.lastName, 80) || undefined,
      });
      await audit(ctx.db, r.id, r.created ? 'owner.created' : 'owner.password_reset', 'user', r.id, { ip: ctx.ip });
      return [r.created ? 201 : 200, { ok: true, created: r.created, phone: r.phone }];
    } catch (e) {
      if (e.message === 'INVALID_PHONE' || e.message === 'INVALID_PASSWORD') throw new HttpError(400, e.message, { minLength: cfg.passwordMin });
      throw e;
    }
  });
}

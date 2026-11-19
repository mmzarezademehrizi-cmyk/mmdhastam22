// Activity system API on Cloudflare Workers + D1.
// Same endpoints as the old Node server, so the apps only need the new base address.
import { initConfig, cfg, configProblem } from './config.js';
import { Db, ensureSchema } from './db.js';
import { Router, readJson, sendJson, clientIp } from './http.js';
import { authenticate } from './auth.js';
import { registerAuthRoutes } from './routes_auth.js';
import { registerOwnerRoutes } from './routes_owner.js';
import { registerDataRoutes } from './routes_data.js';
import { registerSetupRoutes } from './routes_setup.js';
import { HttpError, RateLimiter } from './util.js';

const limiter = new RateLimiter();
const router = new Router();
const app = { limiter };
registerAuthRoutes(router, app);
registerOwnerRoutes(router, app);
registerDataRoutes(router, app);
registerSetupRoutes(router, app);

export async function handle(request, env) {
  initConfig(env);
  try {
    const url = new URL(request.url);
    let path = url.pathname;
    if (cfg.basePath) {
      if (path === cfg.basePath) path = '/';
      else if (path.startsWith(cfg.basePath + '/')) path = path.slice(cfg.basePath.length);
      else throw new HttpError(404, 'NOT_FOUND');
    }

    // A friendly answer for "is it deployed?" even before the Worker is fully configured.
    if (path === '/' && request.method === 'GET') {
      return sendJson(200, { ok: true, service: 'activity-system-api', configured: !configProblem() && Boolean(env.DB) });
    }

    const found = router.match(request.method, path);
    if (!found) throw new HttpError(404, 'NOT_FOUND');
    if (found === 'METHOD') throw new HttpError(405, 'METHOD_NOT_ALLOWED');

    const problem = configProblem();
    if (problem) return sendJson(503, { error: 'SERVER_NOT_CONFIGURED', hint: problem });
    if (!env.DB) return sendJson(503, { error: 'DATABASE_NOT_CONNECTED', hint: 'Add a D1 binding named DB' });

    const db = new Db(env.DB);
    await ensureSchema(db);

    const ip = clientIp(request);
    limiter.check(`ip:${ip}`, 600, 60_000);

    const ctx = {
      req: request, db, limiter, ip,
      params: found.params,
      query: Object.fromEntries(url.searchParams),
      body: ['POST', 'PUT', 'PATCH'].includes(request.method) ? await readJson(request) : {},
      user: null,
    };
    if (found.route.opts.auth) ctx.user = await authenticate(ctx, found.route.opts);

    const result = await found.route.handler(ctx);
    // handlers answer [status, body] for non-200 replies; a plain list of rows is sent as 200
    if (Array.isArray(result) && result.length === 2 && typeof result[0] === 'number') return sendJson(result[0], result[1]);
    return sendJson(200, result ?? { ok: true });
  } catch (e) {
    if (e instanceof HttpError) return sendJson(e.status, { error: e.code, ...e.extra });
    console.error('Unhandled error:', e && e.stack ? e.stack : e);
    return sendJson(500, { error: 'INTERNAL_SERVER_ERROR' });
  }
}

export default { fetch: handle };

// Settings come from the Worker's variables and secrets (Cloudflare dashboard or install-proje panel).
//   APP_JWT_SECRET  (secret, >= 32 characters)   SETUP_KEY (secret, used once to create the owner)
//   BASE_PATH       (default "/appfaaliat")      SMS_PROVIDER (console | kavenegar | webhook)
//   SESSION_DAYS, SMS_OTP_LENGTH, KAVENEGAR_API_KEY, KAVENEGAR_TEMPLATE, SMS_WEBHOOK_URL, SMS_WEBHOOK_AUTH
//   PBKDF2_ITERATIONS (default 100000 = the maximum Workers allows)

export const cfg = {
  basePath: '/appfaaliat',
  jwtSecret: '',
  setupKey: '',
  sessionDays: 30,
  passwordMin: 8,
  passwordMax: 128,
  pbkdf2Iterations: 100000,
  smsProvider: 'console',
  smsOtpLength: 6,
  kavenegarApiKey: '',
  kavenegarTemplate: '',
  smsWebhookUrl: '',
  smsWebhookAuth: '',
};

let applied = null;

/** Reads the Worker env into cfg (cheap; only re-applied when env changes). */
export function initConfig(env) {
  if (applied === env) return cfg;
  applied = env;
  const base = env.BASE_PATH === undefined ? '/appfaaliat' : String(env.BASE_PATH).trim();
  cfg.basePath = base === '' || base === '/' ? '' : '/' + base.replace(/^\/+|\/+$/g, '');
  cfg.jwtSecret = env.APP_JWT_SECRET || '';
  cfg.setupKey = env.SETUP_KEY || '';
  cfg.sessionDays = Number(env.SESSION_DAYS || 30);
  cfg.pbkdf2Iterations = Math.min(Math.max(Number(env.PBKDF2_ITERATIONS || 100000), 1000), 100000);
  cfg.smsProvider = String(env.SMS_PROVIDER || 'console').toLowerCase();
  cfg.smsOtpLength = Number(env.SMS_OTP_LENGTH || 6);
  cfg.kavenegarApiKey = env.KAVENEGAR_API_KEY || '';
  cfg.kavenegarTemplate = env.KAVENEGAR_TEMPLATE || '';
  cfg.smsWebhookUrl = env.SMS_WEBHOOK_URL || '';
  cfg.smsWebhookAuth = env.SMS_WEBHOOK_AUTH || '';
  return cfg;
}

export function configProblem() {
  return cfg.jwtSecret.length < 32 ? 'APP_JWT_SECRET is missing or shorter than 32 characters' : null;
}

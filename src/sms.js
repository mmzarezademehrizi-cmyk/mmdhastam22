import { cfg } from './config.js';

/** +98912... -> 0912... (what Iranian SMS panels expect) */
function toLocalIran(phone) {
  return phone.startsWith('+98') ? '0' + phone.slice(3) : phone;
}

export function smsProviderReady() {
  switch (cfg.smsProvider) {
    case 'kavenegar': return Boolean(cfg.kavenegarApiKey && cfg.kavenegarTemplate);
    case 'webhook': return Boolean(cfg.smsWebhookUrl);
    default: return false; // console = test mode, nothing is really sent
  }
}

async function fetchJson(url, init) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10_000);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** Sends the one-time code. Throws on failure. */
export async function sendOtp(phone, code) {
  switch (cfg.smsProvider) {
    case 'console':
      console.log(`[SMS:console] OTP for ${phone}: ${code}`);
      return;

    case 'kavenegar': {
      // https://kavenegar.com  "verify/lookup" with an approved template that contains %token
      const url = `https://api.kavenegar.com/v1/${cfg.kavenegarApiKey}/verify/lookup.json` +
        `?receptor=${encodeURIComponent(toLocalIran(phone))}&token=${encodeURIComponent(code)}` +
        `&template=${encodeURIComponent(cfg.kavenegarTemplate)}`;
      const res = await fetchJson(url, { method: 'GET' });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || body?.return?.status !== 200) {
        throw new Error(`kavenegar failed: ${res.status} ${body?.return?.message ?? ''}`);
      }
      return;
    }

    case 'webhook': {
      // Generic: POST {phone, localPhone, code, message} to your SMS provider/bridge.
      const headers = { 'Content-Type': 'application/json' };
      if (cfg.smsWebhookAuth) headers.Authorization = cfg.smsWebhookAuth;
      const res = await fetchJson(cfg.smsWebhookUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({ phone, localPhone: toLocalIran(phone), code, message: `کد ورود شما: ${code}` }),
      });
      if (!res.ok) throw new Error(`webhook failed: ${res.status}`);
      return;
    }

    default:
      throw new Error(`Unknown SMS_PROVIDER: ${cfg.smsProvider}`);
  }
}

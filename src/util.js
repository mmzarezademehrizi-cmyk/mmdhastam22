import { cfg } from './config.js';

export class HttpError extends Error {
  constructor(status, code, extra = {}) {
    super(code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export const nowIso = () => new Date().toISOString();
export const addMs = (ms) => new Date(Date.now() + ms).toISOString();

const enc = new TextEncoder();
const dec = new TextDecoder();

// ───────────── base64 helpers ─────────────
export function bytesToB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
export function b64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
const b64uFromBytes = (bytes) => bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uToBytes = (s) => b64ToBytes(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
const b64uFromString = (s) => b64uFromBytes(enc.encode(s));
const b64uToString = (s) => dec.decode(b64uToBytes(s));

export async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text)));
}

export function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** Uniform random integer in [0, max). */
export function randomInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return buf[0] % max;
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

export async function hmacHex(secret, data) {
  return toHex(await hmac(secret, data));
}

// ───────────── JWT (HS256) ─────────────
export async function signJwt(payload, secret, ttlSeconds) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const iat = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat, exp: iat + ttlSeconds };
  const data = `${b64uFromString(JSON.stringify(header))}.${b64uFromString(JSON.stringify(body))}`;
  return `${data}.${b64uFromBytes(await hmac(secret, data))}`;
}

export async function verifyJwt(token, secret) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  try {
    const expected = await hmac(secret, `${parts[0]}.${parts[1]}`);
    if (!timingSafeEqual(b64uToBytes(parts[2]), expected)) return null;
    const header = JSON.parse(b64uToString(parts[0]));
    if (header.alg !== 'HS256') return null;
    const payload = JSON.parse(b64uToString(parts[1]));
    if (typeof payload.exp !== 'number' || payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch { return null; }
}

// ───────────── passwords (PBKDF2-SHA256, native WebCrypto) ─────────────
async function pbkdf2(password, salt, iterations, bytes = 32) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, bytes * 8));
}

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const it = cfg.pbkdf2Iterations;
  const key = await pbkdf2(password, salt, it);
  return `pbkdf2$${it}$${bytesToB64(salt)}$${bytesToB64(key)}`;
}

export async function verifyPassword(password, stored) {
  const p = String(stored || '').split('$');
  if (p.length !== 4 || p[0] !== 'pbkdf2') return false;
  const it = Number(p[1]);
  if (!Number.isInteger(it) || it < 1000 || it > 100000) return false;
  const expected = b64ToBytes(p[3]);
  const actual = await pbkdf2(password, b64ToBytes(p[2]), it, expected.length);
  return timingSafeEqual(actual, expected);
}

let dummyHash;
/** Unknown phone numbers cost the same time as real ones. */
export async function dummyVerify(password) {
  dummyHash ??= await hashPassword(toHex(randomBytes(8)));
  await verifyPassword(password, dummyHash);
}

// ───────────── phone ─────────────
const FA = '۰۱۲۳۴۵۶۷۸۹';
const AR = '٠١٢٣٤٥٦٧٨٩';

/** 0912..., ۰۹۱۲..., +98912... -> +98912...  (null when invalid) */
export function normalizePhone(input) {
  let p = String(input ?? '').trim()
    .replace(/[۰-۹]/g, (d) => String(FA.indexOf(d)))
    .replace(/[٠-٩]/g, (d) => String(AR.indexOf(d)))
    .replace(/[\s\-()]/g, '');
  if (p.startsWith('00')) p = '+' + p.slice(2);
  if (/^09\d{9}$/.test(p)) p = '+98' + p.slice(1);
  else if (/^9\d{9}$/.test(p)) p = '+98' + p;
  else if (/^989\d{9}$/.test(p)) p = '+' + p;
  return /^\+[1-9]\d{7,14}$/.test(p) ? p : null;
}

export function isValidNationalId(input) {
  const s = String(input ?? '').trim()
    .replace(/[۰-۹]/g, (d) => String(FA.indexOf(d)))
    .replace(/[٠-٩]/g, (d) => String(AR.indexOf(d)));
  if (!/^\d{10}$/.test(s) || /^(\d)\1{9}$/.test(s)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += Number(s[i]) * (10 - i);
  const r = sum % 11;
  return r < 2 ? Number(s[9]) === r : Number(s[9]) === 11 - r;
}

// ───────────── misc ─────────────
export const round2 = (v) => Math.round(v * 100) / 100;

export function applyRule(rule, raw) {
  if (!rule) return round2(raw);
  switch (rule.operation) {
    case 'add': return round2(raw + rule.add_hours);
    case 'multiply': return round2(raw * rule.multiplier);
    case 'add_then_multiply': return round2((raw + rule.add_hours) * rule.multiplier);
    default: return round2(raw);
  }
}

export const isIsoDate = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));

/** In-memory limiter (per Worker instance): at most [max] hits per [windowMs] for a key. */
export class RateLimiter {
  constructor() { this.hits = new Map(); }
  check(key, max, windowMs) {
    const now = Date.now();
    const cur = this.hits.get(key);
    if (!cur || cur.reset <= now) {
      if (this.hits.size > 5000) this.sweep();
      this.hits.set(key, { count: 1, reset: now + windowMs });
      return;
    }
    cur.count++;
    if (cur.count > max) {
      throw new HttpError(429, 'RATE_LIMITED', { retryAfterSeconds: Math.ceil((cur.reset - now) / 1000) });
    }
  }
  sweep() {
    const now = Date.now();
    for (const [k, v] of this.hits) if (v.reset <= now) this.hits.delete(k);
  }
}

export function cleanText(v, max = 500) {
  if (v === undefined || v === null) return '';
  return String(v).trim().slice(0, max);
}

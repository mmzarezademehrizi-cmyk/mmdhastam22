import { nowIso } from './util.js';

// Thin wrapper that gives Cloudflare D1 the same shape the Node/SQLite version used:
//   db.prepare(sql).get(...args) / .all(...args) / .run(...args)   (all async)
//   db.prepare(sql).bind(...args) -> a statement you can put in db.batch([...]) (one atomic transaction)

const clean = (args) => args.map((v) => (v === undefined ? null : v));

class Stmt {
  constructor(d1, sql, args = []) {
    this.d1 = d1;
    this.sql = sql;
    this.args = args;
  }

  bind(...args) {
    return new Stmt(this.d1, this.sql, clean(args));
  }

  _prepared() {
    return this.d1.prepare(this.sql).bind(...this.args);
  }

  async get(...args) {
    const s = args.length ? this.bind(...args) : this;
    return (await s._prepared().first()) ?? undefined;
  }

  async all(...args) {
    const s = args.length ? this.bind(...args) : this;
    const r = await s._prepared().all();
    return r.results ?? [];
  }

  async run(...args) {
    const s = args.length ? this.bind(...args) : this;
    const r = await s._prepared().run();
    return { changes: r.meta?.changes ?? 0, lastInsertRowid: r.meta?.last_row_id };
  }
}

export class Db {
  constructor(d1) {
    this.d1 = d1;
  }

  prepare(sql) {
    return new Stmt(this.d1, sql);
  }

  /** All statements succeed or none does. */
  async batch(statements) {
    if (!statements.length) return [];
    return this.d1.batch(statements.map((s) => s._prepared()));
  }
}

// ───────────── schema (created automatically on the first request) ─────────────
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL UNIQUE,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('owner','admin','operator','user')),
    is_active INTEGER NOT NULL DEFAULT 1,
    password_hash TEXT,
    must_set_password INTEGER NOT NULL DEFAULT 1,
    password_updated_at TEXT,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    profile_json TEXT NOT NULL DEFAULT '{}',
    device_json TEXT NOT NULL DEFAULT '{}',
    created_by INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    policy_json TEXT NOT NULL DEFAULT '{}'
  )`,
  `CREATE TABLE IF NOT EXISTS sessions(
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    auth_method TEXT NOT NULL CHECK (auth_method IN ('otp','password'))
  )`,
  'CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)',
  `CREATE TABLE IF NOT EXISTS otp_codes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    used_at TEXT
  )`,
  'CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_codes(phone, created_at)',
  'CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)',
  `CREATE TABLE IF NOT EXISTS presence(
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    last_seen_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS members(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_by INTEGER NOT NULL REFERENCES users(id),
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    father_name TEXT,
    national_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`,
  'CREATE INDEX IF NOT EXISTS idx_members_owner ON members(created_by)',
  `CREATE TABLE IF NOT EXISTS categories(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    day_mode TEXT NOT NULL DEFAULT 'every',
    days TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6'
  )`,
  `CREATE TABLE IF NOT EXISTS calculation_rules(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('none','add','multiply','add_then_multiply')),
    add_hours REAL NOT NULL DEFAULT 0,
    multiplier REAL NOT NULL DEFAULT 1,
    effective_from TEXT NOT NULL,
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE(category_id, version)
  )`,
  `CREATE TABLE IF NOT EXISTS activities(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_by INTEGER NOT NULL REFERENCES users(id),
    category_id INTEGER NOT NULL REFERENCES categories(id),
    activity_date TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL
  )`,
  'CREATE INDEX IF NOT EXISTS idx_activities_date ON activities(activity_date)',
  'CREATE INDEX IF NOT EXISTS idx_activities_owner ON activities(created_by)',
  `CREATE TABLE IF NOT EXISTS activity_entries(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    activity_id INTEGER NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
    member_id INTEGER NOT NULL REFERENCES members(id),
    raw_hours REAL NOT NULL CHECK (raw_hours >= 0),
    applied_rule_id INTEGER REFERENCES calculation_rules(id),
    final_hours REAL NOT NULL CHECK (final_hours >= 0),
    created_at TEXT NOT NULL
  )`,
  'CREATE INDEX IF NOT EXISTS idx_entries_member ON activity_entries(member_id)',
  'CREATE INDEX IF NOT EXISTS idx_entries_activity ON activity_entries(activity_id)',
  `CREATE TABLE IF NOT EXISTS audit_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
  )`,
  'CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at)',
  'CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_id, created_at)',
];

const SCHEMA_VERSION = 2;
let ready = false;

/** Creates / updates the tables once per Worker instance. Safe to run any number of times. */
export async function ensureSchema(db) {
  if (ready) return;
  const d1 = db.d1;
  await d1.prepare('CREATE TABLE IF NOT EXISTS _schema(id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)').run();
  const row = await d1.prepare('SELECT version FROM _schema WHERE id = 1').first();
  if (!row || row.version < SCHEMA_VERSION) {
    await d1.batch(SCHEMA.map((s) => d1.prepare(s)));
    // A database imported from the old server (v1) misses the v2 columns: add them if needed.
    const addColumn = async (table, column, ddl) => {
      const cols = await d1.prepare(`PRAGMA table_info(${table})`).all();
      if (!cols.results.some((c) => c.name === column)) await d1.prepare(`ALTER TABLE ${table} ADD COLUMN ${ddl}`).run();
    };
    await addColumn('categories', 'day_mode', "day_mode TEXT NOT NULL DEFAULT 'every'");
    await addColumn('categories', 'days', "days TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6'");
    await addColumn('users', 'policy_json', "policy_json TEXT NOT NULL DEFAULT '{}'");
    await d1.prepare('INSERT INTO _schema(id, version) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET version = excluded.version').bind(SCHEMA_VERSION).run();
  }
  ready = true;
}

export async function getSetting(db, key, fallback = null) {
  const r = await db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return r ? r.value : fallback;
}

export async function setSetting(db, key, value) {
  await db.prepare('INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, String(value));
}

export function auditStmt(db, actorId, action, entityType, entityId, details = {}) {
  return db.prepare('INSERT INTO audit_logs(actor_id, action, entity_type, entity_id, details, created_at) VALUES(?,?,?,?,?,?)')
    .bind(actorId ?? null, action, entityType, entityId === undefined || entityId === null ? null : String(entityId), JSON.stringify(details), nowIso());
}

export async function audit(db, actorId, action, entityType, entityId, details = {}) {
  await auditStmt(db, actorId, action, entityType, entityId, details).run();
}

/** Housekeeping: old sessions and one-time codes. */
export async function cleanup(db) {
  const week = new Date(Date.now() - 7 * 86400_000).toISOString();
  await db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(week);
  await db.prepare('DELETE FROM otp_codes WHERE created_at < ?').run(new Date(Date.now() - 86400_000).toISOString());
}

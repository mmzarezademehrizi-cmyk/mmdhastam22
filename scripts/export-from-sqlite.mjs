// Moves the data of the OLD Node server (SQLite file) into the new D1 database.
//   node scripts/export-from-sqlite.mjs /app/data/app.db > import.sql
//   npx wrangler d1 execute activity-db --remote --file=import.sql
// Run it AFTER the Worker answered at least once (it creates the tables).
// Sessions / one-time codes are not copied. Password hashes are NOT copied either (the old format
// cannot be checked by Workers): every user gets "no password" and must be given a new one by the owner.
import { DatabaseSync } from 'node:sqlite';

const file = process.argv[2];
if (!file) {
  console.error('Usage: node scripts/export-from-sqlite.mjs path/to/app.db > import.sql');
  process.exit(1);
}
const db = new DatabaseSync(file, { readOnly: true });
const q = (v) => {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number' || typeof v === 'bigint') return String(v);
  return `'${String(v).replace(/'/g, "''")}'`;
};
const tables = [
  ['users', ['id', 'phone', 'first_name', 'last_name', 'role', 'is_active', 'must_set_password', 'password_updated_at', 'profile_json', 'device_json', 'created_by', 'created_at', 'updated_at', 'policy_json']],
  ['settings', ['key', 'value']],
  ['members', ['id', 'created_by', 'first_name', 'last_name', 'father_name', 'national_id', 'created_at', 'updated_at']],
  ['categories', ['id', 'title', 'is_active', 'sort_order', 'created_at', 'day_mode', 'days']],
  ['calculation_rules', ['id', 'category_id', 'version', 'operation', 'add_hours', 'multiplier', 'effective_from', 'created_by', 'created_at']],
  ['activities', ['id', 'created_by', 'category_id', 'activity_date', 'note', 'created_at']],
  ['activity_entries', ['id', 'activity_id', 'member_id', 'raw_hours', 'applied_rule_id', 'final_hours', 'created_at']],
  ['audit_logs', ['id', 'actor_id', 'action', 'entity_type', 'entity_id', 'details', 'created_at']],
];
const have = (t) => db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?").get(t);
const columnsOf = (t) => db.prepare(`PRAGMA table_info(${t})`).all().map((c) => c.name);
console.log('PRAGMA defer_foreign_keys = on;');
for (const [table, wanted] of tables) {
  if (!have(table)) continue;
  const present = new Set(columnsOf(table));
  const cols = wanted.filter((c) => present.has(c));
  for (const row of db.prepare(`SELECT ${cols.join(', ')} FROM ${table}`).all()) {
    console.log(`INSERT OR REPLACE INTO ${table}(${cols.join(', ')}) VALUES(${cols.map((c) => q(row[c])).join(', ')});`);
  }
}
console.error('Done. Passwords were not copied: set a new password for each user in the owner app.');

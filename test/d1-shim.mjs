// Minimal Cloudflare D1 stand-in on top of node:sqlite (tests only). It also enforces D1's limit of 100 bound values.
import { DatabaseSync } from 'node:sqlite';

class Prepared {
  constructor(db, sql, args = []) { this.db = db; this.sql = sql; this.args = args; }
  bind(...args) {
    if (args.length > 100) throw new Error('D1_ERROR: too many SQL variables (max 100)');
    if (args.some((a) => a === undefined)) throw new Error('D1_TYPE_ERROR: undefined is not allowed');
    return new Prepared(this.db, this.sql, args);
  }
  async first() { return this.db.prepare(this.sql).get(...this.args) ?? null; }
  async all() { return { results: this.db.prepare(this.sql).all(...this.args).map((r) => ({ ...r })), meta: {} }; }
  async run() {
    const r = this.db.prepare(this.sql).run(...this.args);
    return { success: true, meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
  }
}

export class D1Shim {
  constructor() {
    this.db = new DatabaseSync(':memory:');
    this.db.exec('PRAGMA foreign_keys = ON');
  }
  prepare(sql) { return new Prepared(this.db, sql); }
  async batch(statements) {
    this.db.exec('BEGIN');
    try {
      const out = [];
      for (const s of statements) out.push(await s.run());
      this.db.exec('COMMIT');
      return out;
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }
}

import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import { env } from '$env/dynamic/private';
import * as schema from './schema';

export type Db = ReturnType<typeof createDb>;

export function createDb(path: string) {
  const sqlite = new Database(path);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  sqlite.pragma('synchronous = NORMAL');
  return drizzle(sqlite, { schema });
}

export function applyMigrations(db: Db, migrationsFolder = './src/lib/server/db/migrations') {
  migrate(db, { migrationsFolder });
}

export { schema };

let _db: Db | null = null;
export function getDb(): Db {
  if (!_db) {
    _db = createDb(env.DATABASE_URL ?? './finance.db');
    applyMigrations(_db);
  }
  return _db;
}

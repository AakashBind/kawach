import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { CONFIG } from '../config.js';

const dbDir = path.dirname(CONFIG.DATABASE_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

export const db = new Database(CONFIG.DATABASE_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export function initDatabase() {
  const possiblePaths = [
    path.join(__dirname, 'schema.sql'),
    path.join(__dirname, '..', 'src', 'database', 'schema.sql'),
    path.join(process.cwd(), 'src', 'database', 'schema.sql'),
    path.join(process.cwd(), 'dist', 'database', 'schema.sql'),
    path.join(process.cwd(), 'backend', 'src', 'database', 'schema.sql'),
    path.join(process.cwd(), 'backend', 'dist', 'database', 'schema.sql'),
    path.join(__dirname, '../../src/database/schema.sql')
  ];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      const schemaSql = fs.readFileSync(p, 'utf-8');
      db.exec(schemaSql);
      return;
    }
  }
}

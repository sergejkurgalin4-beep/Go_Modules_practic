import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const usersTable = name => `
CREATE TABLE ${name} (
  id                 INTEGER PRIMARY KEY,
  login              TEXT    NOT NULL UNIQUE,            -- в нижнем регистре
  snils_digits       TEXT    UNIQUE,                     -- 11 цифр, без разделителей
  password_hash      TEXT    NOT NULL,                   -- scrypt$N$r$p$salt$key
  full_name          TEXT    NOT NULL,
  short_name         TEXT    NOT NULL,
  position           TEXT    NOT NULL,
  short_position     TEXT    NOT NULL,
  role               TEXT    NOT NULL CHECK (role IN ('head', 'hq', 'commander', 'admin')),
  employee_code      TEXT,
  personnel_number   TEXT,
  phone              TEXT,
  email              TEXT,
  department         TEXT,
  appointment_order  TEXT,
  clearance          TEXT,
  workstation        TEXT,
  failed_attempts    INTEGER NOT NULL DEFAULT 0,
  locked_until       INTEGER,
  is_active          INTEGER NOT NULL DEFAULT 1
)
`;

const SCHEMA = `

-- Ключевые носители КЭП (токены). PIN хранится только в виде хэша.
CREATE TABLE IF NOT EXISTS tokens (
  id                 INTEGER PRIMARY KEY,
  serial             TEXT    NOT NULL UNIQUE,
  model              TEXT    NOT NULL,
  user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pin_hash           TEXT    NOT NULL,
  pin_attempts_left  INTEGER NOT NULL DEFAULT 3,
  locked             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS certificates (
  id                 INTEGER PRIMARY KEY,
  user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_id           INTEGER REFERENCES tokens(id) ON DELETE SET NULL,
  serial_number      TEXT    NOT NULL,
  issuer             TEXT    NOT NULL,
  thumbprint         TEXT    NOT NULL,
  valid_from         INTEGER NOT NULL,
  valid_to           INTEGER NOT NULL,
  status             TEXT    NOT NULL DEFAULT 'valid' CHECK (status IN ('valid', 'revoked'))
);

CREATE TABLE IF NOT EXISTS delegations (
  id                 INTEGER PRIMARY KEY,
  user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title              TEXT    NOT NULL,
  position           INTEGER NOT NULL DEFAULT 0
);

-- Сеансы. В базе лежит только SHA-256 от токена из cookie, сам токен не хранится.
CREATE TABLE IF NOT EXISTS sessions (
  id                 TEXT    PRIMARY KEY,
  user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  method             TEXT    NOT NULL CHECK (method IN ('password', 'kep')),
  ip                 TEXT,
  user_agent         TEXT,
  created_at         INTEGER NOT NULL,
  last_seen_at       INTEGER NOT NULL,
  expires_at         INTEGER NOT NULL,
  ended_at           INTEGER,
  end_reason         TEXT    CHECK (end_reason IN ('logout', 'timeout', 'forced'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, created_at DESC);

-- Журнал событий безопасности (вход, ошибки, блокировки, выход).
CREATE TABLE IF NOT EXISTS audit_log (
  id                 INTEGER PRIMARY KEY,
  user_id            INTEGER REFERENCES users(id) ON DELETE SET NULL,
  event              TEXT    NOT NULL,
  method             TEXT,
  identifier         TEXT,
  ip                 TEXT,
  user_agent         TEXT,
  details            TEXT,
  created_at         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at DESC);
`;

export function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.transaction = fn => (...args) => {
    db.exec('BEGIN');
    try {
      const result = fn(...args);
      db.exec('COMMIT');
      return result;
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  };
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'").get()) {
    db.exec(usersTable('users'));
  }
  migrateRoles(db);
  db.exec(SCHEMA);
  return db;
}

function migrateRoles(db) {
  const { sql } = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").get();
  if (sql.includes("'admin'")) return;

  db.exec('PRAGMA foreign_keys = OFF');
  try {
    db.transaction(() => {
      db.exec(usersTable('users_new'));
      db.exec('INSERT INTO users_new SELECT * FROM users');
      db.exec('DROP TABLE users');
      db.exec('ALTER TABLE users_new RENAME TO users');
    })();
    if (db.prepare('PRAGMA foreign_key_check').all().length) throw new Error('Миграция нарушила связи между таблицами');
  } finally {
    db.exec('PRAGMA foreign_keys = ON');
  }
}

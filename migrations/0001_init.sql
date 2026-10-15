-- Anvil — konta uczniów i postęp. Migracja 2026-10-15.

CREATE TABLE IF NOT EXISTS users (
  id          TEXT PRIMARY KEY,          -- uuid
  handle      TEXT NOT NULL UNIQUE,      -- nick, tak jak w UI
  email       TEXT NOT NULL UNIQUE,      -- lowercase, unikalny
  pw_salt     TEXT NOT NULL,             -- hex, 16 bajtów losowych
  pw_hash     TEXT NOT NULL,             -- PBKDF2-SHA256, 210k iteracji
  created_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,          -- 32 bajty losowe, w cookie HttpOnly
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS progress (
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  task_id     TEXT NOT NULL,
  passed      INTEGER NOT NULL DEFAULT 0,
  points      INTEGER,
  attempts    INTEGER NOT NULL DEFAULT 0,
  hints_used  INTEGER NOT NULL DEFAULT 0,
  code        TEXT,                      -- ostatni kod ucznia (do wznawiania)
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, task_id)
);

CREATE TABLE IF NOT EXISTS streak (
  user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  days        TEXT NOT NULL,             -- lista dat 'YYYY-MM-DD', po przecinku
  best        INTEGER NOT NULL DEFAULT 0
);
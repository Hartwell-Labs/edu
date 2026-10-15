-- Anvil — potwierdzenie e-mail i plany. Migracja 2026-10-15.

ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free';       -- free | lifetime
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN verify_token TEXT;
ALTER TABLE users ADD COLUMN verify_sent_at INTEGER NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_verify ON users(verify_token) WHERE verify_token IS NOT NULL;

-- dziennik wysłanych maili (do diagnostyki, nic wrażliwego)
CREATE TABLE IF NOT EXISTS mail_outbox (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  to_addr     TEXT NOT NULL,
  subject     TEXT NOT NULL,
  kind        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
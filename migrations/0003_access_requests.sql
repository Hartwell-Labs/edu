-- Anvil — prosby o dostep do drugiego tieru. 2026-10-16.
--
-- Swiadomie BEZ tabeli platnosci: nie mamy procesora, a falszywy checkout
-- jest gorszy niz jego brak. Prosba laduje tutaj, admin nadaje plan przez
-- `admin.py grant <handle> lifetime`. Miejsce na Stripe jest jedno i nazwane.

CREATE TABLE IF NOT EXISTS access_requests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,  -- NULL = gosc bez konta
  handle      TEXT,                                          -- jak podal w formularzu
  email       TEXT NOT NULL,
  why         TEXT,                                          -- po co mu drugi tier
  status      TEXT NOT NULL DEFAULT 'open',                 -- open | granted | declined
  note        TEXT,                                          -- co uslyszymy w odpowiedzi
  created_at  INTEGER NOT NULL,
  handled_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_access_email  ON access_requests(email);
CREATE INDEX IF NOT EXISTS idx_access_status ON access_requests(status, created_at);

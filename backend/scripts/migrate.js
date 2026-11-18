// CampusGate — Database schema migration
import { db } from '../db.js';

export function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id                  TEXT PRIMARY KEY,
      roll_number         TEXT UNIQUE NOT NULL,
      name                TEXT NOT NULL,
      email               TEXT UNIQUE NOT NULL,
      phone               TEXT,
      role                TEXT NOT NULL DEFAULT 'student',
      program             TEXT,
      year                TEXT,
      hostel_block        TEXT,
      room_no             TEXT,
      is_enrolled         INTEGER NOT NULL DEFAULT 1,
      is_active_resident  INTEGER NOT NULL DEFAULT 1,
      tenancy_expires_at  INTEGER,
      fee_status          TEXT DEFAULT 'PENDING',
      password_hash       TEXT NOT NULL,
      totp_secret         TEXT,
      totp_enrolled       INTEGER NOT NULL DEFAULT 1,
      backup_codes        TEXT,
      failed_logins       INTEGER NOT NULL DEFAULT 0,
      locked_until        INTEGER DEFAULT 0,
      status              TEXT NOT NULL DEFAULT 'ACTIVE',
      activation_code     TEXT,
      created_at          INTEGER NOT NULL,
      last_login_at       INTEGER,
      last_login_location TEXT,
      last_login_ip       TEXT
    );

    CREATE TABLE IF NOT EXISTS services (
      id              TEXT PRIMARY KEY,
      name            TEXT NOT NULL,
      description     TEXT,
      icon            TEXT,
      required_claims TEXT NOT NULL,
      purpose         TEXT NOT NULL,
      status          TEXT NOT NULL DEFAULT 'ACTIVE',
      created_at      INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS consents (
      id             TEXT PRIMARY KEY,
      user_id        TEXT NOT NULL,
      service_id     TEXT NOT NULL,
      granted_claims TEXT NOT NULL,
      pairwise_id    TEXT NOT NULL,
      granted_at     INTEGER NOT NULL,
      revoked        INTEGER NOT NULL DEFAULT 0,
      revoked_at     INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (service_id) REFERENCES services(id),
      UNIQUE(user_id, service_id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id             TEXT PRIMARY KEY,
      user_id        TEXT NOT NULL,
      refresh_token  TEXT UNIQUE NOT NULL,
      device_label   TEXT,
      user_agent     TEXT,
      ip             TEXT,
      location       TEXT,
      created_at     INTEGER NOT NULL,
      last_used_at   INTEGER NOT NULL,
      expires_at     INTEGER NOT NULL,
      revoked        INTEGER NOT NULL DEFAULT 0,
      revoked_reason TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS used_refresh_tokens (
      token        TEXT PRIMARY KEY,
      session_id   TEXT NOT NULL,
      user_id      TEXT NOT NULL,
      consumed_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id           TEXT PRIMARY KEY,
      seq          INTEGER NOT NULL UNIQUE,
      prev_hash    TEXT NOT NULL,
      current_hash TEXT NOT NULL,
      timestamp    INTEGER NOT NULL,
      user_id      TEXT,
      actor        TEXT NOT NULL,
      action       TEXT NOT NULL,
      target       TEXT,
      service_id   TEXT,
      claim        TEXT,
      ip           TEXT,
      device       TEXT,
      meta         TEXT
    );

    CREATE TABLE IF NOT EXISTS recovery_events (
      id                  TEXT PRIMARY KEY,
      user_id             TEXT NOT NULL,
      type                TEXT NOT NULL,
      status              TEXT NOT NULL,
      cooling_off_until   INTEGER,
      meta                TEXT,
      cancellation_token  TEXT,
      created_at          INTEGER NOT NULL,
      completed_at        INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS anomaly_alerts (
      id           TEXT PRIMARY KEY,
      user_id      TEXT,
      severity     TEXT NOT NULL,
      anomaly_type TEXT NOT NULL,
      description  TEXT NOT NULL,
      ip           TEXT,
      status       TEXT NOT NULL DEFAULT 'OPEN',
      created_at   INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS demo_library_loans (
      id           TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL,
      book_title   TEXT NOT NULL,
      isbn         TEXT NOT NULL,
      borrowed_at  INTEGER NOT NULL,
      due_date     INTEGER NOT NULL,
      returned     INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS demo_fee_invoices (
      id           TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL,
      description  TEXT NOT NULL,
      amount       REAL NOT NULL,
      status       TEXT NOT NULL,
      paid_at      INTEGER,
      tx_hash      TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(seq);
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, timestamp);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_consents_user ON consents(user_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_user ON anomaly_alerts(user_id);
  `);
}

if (import.meta.url === import.meta.resolve(import.meta.url)) {
  migrate();
  console.log('Schema migrated OK');
}

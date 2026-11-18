// CampusGate — Database layer (node:sqlite, cryptographic hash-chained audit)
import { DatabaseSync } from 'node:sqlite';
import { randomUUID, createHash, createHmac } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.DB_PATH || join(__dirname, 'data', 'campusgate.db');

mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA foreign_keys = ON');
db.exec('PRAGMA journal_mode = WAL');

export function nowMs() {
  return Date.now();
}

export function uid() {
  return randomUUID();
}

export function queryOne(sql, params = []) {
  const stmt = db.prepare(sql);
  return stmt.get(...params);
}

export function queryAll(sql, params = []) {
  const stmt = db.prepare(sql);
  return stmt.all(...params);
}

export function run(sql, params = []) {
  const stmt = db.prepare(sql);
  return stmt.run(...params);
}

export const GENESIS_HASH = '0'.repeat(64);
const PAIRWISE_SECRET = process.env.PAIRWISE_SECRET || 'campusgate-pairwise-hmac-secret-salt-2026';

// FR-5.5: Pairwise (per-service) user identifiers prevent cross-service tracking
export function generatePairwiseId(userId, serviceId) {
  const hmac = createHmac('sha256', PAIRWISE_SECRET).update(`${userId}:${serviceId}`).digest('hex');
  const prefix = serviceId.slice(0, 3).toLowerCase();
  return `${prefix}-${hmac.slice(0, 12)}`;
}

// FR-7.3: Append-only and tamper-evident audit logging with SHA-256 hash chaining
export function appendAudit({
  user_id = null,
  actor = 'user',
  action,
  target = null,
  service_id = null,
  claim = null,
  ip = '127.0.0.1',
  device = 'Chrome Desktop',
  meta = null,
  timestamp = null,
}) {
  const t = timestamp || nowMs();
  const last = queryOne('SELECT seq, current_hash FROM audit_log ORDER BY seq DESC LIMIT 1');
  const seq = last ? last.seq + 1 : 1;
  const prev_hash = last ? last.current_hash : GENESIS_HASH;
  const entryId = uid();
  const metaStr = meta ? (typeof meta === 'string' ? meta : JSON.stringify(meta)) : null;

  const dataToHash = `${seq}|${prev_hash}|${t}|${actor}|${action}|${target || ''}|${service_id || ''}|${claim || ''}|${ip || ''}|${device || ''}|${metaStr || ''}`;
  const current_hash = createHash('sha256').update(dataToHash).digest('hex');

  const stmt = db.prepare(
    `INSERT INTO audit_log
      (id, seq, prev_hash, current_hash, timestamp, user_id, actor, action, target, service_id, claim, ip, device, meta)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  stmt.run(entryId, seq, prev_hash, current_hash, t, user_id, actor, action, target, service_id, claim, ip, device, metaStr);

  return { id: entryId, seq, prev_hash, current_hash, timestamp: t };
}

// Cryptographic verification of the entire hash chain
export function verifyAuditChain() {
  const entries = queryAll('SELECT * FROM audit_log ORDER BY seq ASC');
  let expectedPrev = GENESIS_HASH;

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.prev_hash !== expectedPrev) {
      return {
        valid: false,
        brokenAtSeq: e.seq,
        brokenId: e.id,
        reason: `Hash pointer broken at block #${e.seq}. Previous hash recorded: ${e.prev_hash.slice(0, 16)}..., expected: ${expectedPrev.slice(0, 16)}...`,
        totalChecked: entries.length,
      };
    }

    const dataToHash = `${e.seq}|${e.prev_hash}|${e.timestamp}|${e.actor}|${e.action}|${e.target || ''}|${e.service_id || ''}|${e.claim || ''}|${e.ip || ''}|${e.device || ''}|${e.meta || ''}`;
    const calculated = createHash('sha256').update(dataToHash).digest('hex');

    if (calculated !== e.current_hash) {
      return {
        valid: false,
        brokenAtSeq: e.seq,
        brokenId: e.id,
        reason: `Cryptographic payload tampered at block #${e.seq} (${e.action})! Recalculated hash: ${calculated.slice(0, 16)}..., stored block hash: ${e.current_hash.slice(0, 16)}...`,
        totalChecked: entries.length,
      };
    }

    expectedPrev = e.current_hash;
  }

  return {
    valid: true,
    totalChecked: entries.length,
    headSeq: entries.length > 0 ? entries[entries.length - 1].seq : 0,
    headHash: expectedPrev,
  };
}

// Demo tool: purposely tamper with an audit entry to demonstrate detection
let tamperBackup = null;

export function tamperAuditLogEntry(seq, forgedAction) {
  const entry = queryOne('SELECT * FROM audit_log WHERE seq = ?', [seq]);
  if (!entry) return null;
  tamperBackup = { ...entry };
  run('UPDATE audit_log SET action = ? WHERE seq = ?', [forgedAction, seq]);
  return { seq, originalAction: entry.action, forgedAction };
}

export function restoreTamperedAuditLog() {
  if (!tamperBackup) return null;
  run('UPDATE audit_log SET action = ? WHERE seq = ?', [tamperBackup.action, tamperBackup.seq]);
  const restored = { ...tamperBackup };
  tamperBackup = null;
  return restored;
}

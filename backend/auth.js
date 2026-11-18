// CampusGate — Authentication & Security Subsystem
import { hash, verify } from 'argon2';
import { authenticator } from 'otplib';
import jwt from 'jsonwebtoken';
import { createHash, randomBytes } from 'node:crypto';
import { nowMs, uid, queryOne, run, queryAll, appendAudit, generatePairwiseId } from './db.js';

const JWT_SECRET = process.env.JWT_SECRET || 'campusgate-jwt-secret-key-2026-secure';
const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SECONDS || 15 * 60); // 15 minutes (FR-6.1)
const REFRESH_TTL_MS = Number(process.env.REFRESH_TTL_MS || 7 * 24 * 60 * 60 * 1000); // 7 days
const STEP_UP_TTL_SECONDS = 5 * 60; // 5 minutes for adaptive step-up
const MAX_FAILED = 5;
const LOCK_MINUTES = 15;

// Breached / weak passwords dictionary (FR-2.3)
const BREACHED_PASSWORDS = new Set([
  'password', 'password123', 'admin123', 'campus123', '12345678', 'qwerty123',
  'student123', 'university2024', 'changeme', 'welcome123', 'testing123'
]);

export function checkBreachedPassword(pw) {
  if (BREACHED_PASSWORDS.has(pw.toLowerCase())) {
    return { breached: true, reason: 'This password is known to be breached in public credential lists.' };
  }
  if (pw.length < 8) {
    return { breached: true, reason: 'Password must be at least 8 characters long.' };
  }
  return { breached: false };
}

// Password hashing with Argon2id (FR-2.3)
export async function hashPassword(password) {
  return hash(password, { type: 2, memoryCost: 65536, timeCost: 3, parallelism: 4 });
}

export async function verifyPassword(passwordHash, password) {
  try {
    return await verify(passwordHash, password);
  } catch {
    return false;
  }
}

// TOTP MFA (FR-2.1)
export function generateTotpSecret() {
  return authenticator.generateSecret();
}

export function totpCheck(secret, token) {
  if (!secret || !token) return false;
  try {
    // Check with 1 step tolerance (+/- 30s)
    authenticator.options = { window: 1 };
    return authenticator.check(token.trim(), secret);
  } catch {
    return false;
  }
}

export function totpCurrentToken(secret) {
  // Helper for live companion demo
  return authenticator.generate(secret);
}

export function totpProvisioningUri(secret, email) {
  return authenticator.keyuri(email, 'CampusGate', secret);
}

// Backup Codes (FR-8.1: stored hashed)
export function hashBackupCode(code) {
  return createHash('sha256').update(code.trim().toUpperCase()).digest('hex');
}

export function generateBackupCodes(count = 8, presetCodes = null) {
  const plainCodes = presetCodes ? [...presetCodes] : [];
  const hashedCodes = [];
  if (presetCodes && presetCodes.length > 0) {
    for (const code of presetCodes) {
      hashedCodes.push(hashBackupCode(code));
    }
  } else {
    for (let i = 0; i < count; i++) {
      const raw = randomBytes(4).toString('hex').toUpperCase();
      const formatted = `${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
      plainCodes.push(formatted);
      hashedCodes.push(hashBackupCode(formatted));
    }
  }
  return { plainCodes, hashedCodes };
}

export function consumeBackupCode(userOrId, codeAttempt) {
  const userId = typeof userOrId === 'object' ? userOrId.id : userOrId;
  const user = queryOne('SELECT id, backup_codes FROM users WHERE id = ?', [userId]);
  if (!user) return false;
  let stored = [];
  try {
    stored = JSON.parse(user.backup_codes || '[]');
  } catch {
    return false;
  }
  const attemptHash = hashBackupCode(codeAttempt);
  const idx = stored.findIndex((h) => h === attemptHash);
  if (idx === -1) return false;
  stored.splice(idx, 1);
  run('UPDATE users SET backup_codes = ? WHERE id = ?', [JSON.stringify(stored), user.id]);
  if (typeof userOrId === 'object') {
    userOrId.backup_codes = JSON.stringify(stored);
  }
  return true;
}

// Brute-force & Lockout Protection (FR-2.5)
export function isLocked(user) {
  if (!user.locked_until) return false;
  return user.failed_logins >= MAX_FAILED && user.locked_until > nowMs();
}

export function bumpFailedLogin(userOrId, ip = '127.0.0.1') {
  const userId = typeof userOrId === 'object' ? userOrId.id : userOrId;
  const current = queryOne('SELECT id, failed_logins, locked_until FROM users WHERE id = ?', [userId]);
  if (!current) return { failedLogins: 0, isLocked: false, lockedUntil: 0 };

  const newFailed = (current.failed_logins || 0) + 1;
  let lockedUntil = current.locked_until || 0;
  if (newFailed >= MAX_FAILED) {
    lockedUntil = nowMs() + LOCK_MINUTES * 60 * 1000;
    // Trigger anomaly alert for brute force
    run(
      `INSERT INTO anomaly_alerts (id, user_id, severity, anomaly_type, description, ip, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?)`,
      [
        uid(),
        current.id,
        'HIGH',
        'BRUTE_FORCE_LOCKOUT',
        `Account locked for ${LOCK_MINUTES}m after ${newFailed} consecutive failed login attempts from ${ip}.`,
        ip,
        nowMs(),
      ]
    );
  }
  run('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?', [newFailed, lockedUntil, current.id]);
  if (typeof userOrId === 'object') {
    userOrId.failed_logins = newFailed;
    userOrId.locked_until = lockedUntil;
  }
  return { failedLogins: newFailed, isLocked: newFailed >= MAX_FAILED, lockedUntil };
}

export function resetFailedLogins(userId) {
  run('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?', [userId]);
}

// Session Management with Rotating Refresh Tokens & Reuse Detection (FR-6.1 - FR-6.4)
export function createSession(user, { deviceLabel = 'Web Browser', userAgent = '', ip = '127.0.0.1', location = 'Campus Wi-Fi' }) {
  const sessionId = uid();
  const refreshToken = `rt_${randomBytes(32).toString('hex')}`;
  const now = nowMs();
  const expiresAt = now + REFRESH_TTL_MS;

  run(
    `INSERT INTO sessions
      (id, user_id, refresh_token, device_label, user_agent, ip, location, created_at, last_used_at, expires_at, revoked)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
    [sessionId, user.id, refreshToken, deviceLabel, userAgent, ip, location, now, now, expiresAt]
  );

  appendAudit({
    user_id: user.id,
    actor: 'user',
    action: 'SESSION.CREATED',
    target: sessionId,
    ip,
    device: deviceLabel,
    meta: { location, expiresAt },
  });

  return { sessionId, refreshToken, expiresAt };
}

export function rotateRefreshToken(oldRefreshToken, { ip = '127.0.0.1', userAgent = '' } = {}) {
  // Check if old token was already consumed -> REPLAY / REUSE DETECTED!
  const reused = queryOne('SELECT * FROM used_refresh_tokens WHERE token = ?', [oldRefreshToken]);
  if (reused) {
    // IMMEDIATE MITIGATION: Revoke all sessions for this user!
    run(
      "UPDATE sessions SET revoked = 1, revoked_reason = 'token_reuse_detected' WHERE user_id = ?",
      [reused.user_id]
    );

    run(
      `INSERT INTO anomaly_alerts (id, user_id, severity, anomaly_type, description, ip, status, created_at)
       VALUES (?, ?, 'CRITICAL', 'TOKEN_REUSE_HIJACK', ?, ?, 'OPEN', ?)`,
      [
        uid(),
        reused.user_id,
        `Replay attack detected: consumed refresh token re-submitted from ${ip}. All user sessions automatically revoked!`,
        ip,
        nowMs(),
      ]
    );

    appendAudit({
      user_id: reused.user_id,
      actor: 'attacker',
      action: 'TOKEN.REPLAY_DETECTED',
      target: reused.session_id,
      ip,
      device: userAgent,
      meta: { alert: 'All sessions terminated due to token reuse detection' },
    });

    throw new Error('SECURITY_ALERT_TOKEN_REUSE: Replay attack detected. Session invalidated for safety.');
  }

  const session = queryOne('SELECT * FROM sessions WHERE refresh_token = ?', [oldRefreshToken]);
  if (!session) {
    throw new Error('INVALID_TOKEN: Session not found');
  }

  if (session.revoked) {
    throw new Error(`SESSION_REVOKED: Session was revoked (${session.revoked_reason || 'logout'})`);
  }

  if (session.expires_at <= nowMs()) {
    throw new Error('SESSION_EXPIRED: Refresh token expired');
  }

  // Issue new token and record old token into used_refresh_tokens
  const newRefreshToken = `rt_${randomBytes(32).toString('hex')}`;
  const now = nowMs();

  run('INSERT INTO used_refresh_tokens (token, session_id, user_id, consumed_at) VALUES (?, ?, ?, ?)', [
    oldRefreshToken,
    session.id,
    session.user_id,
    now,
  ]);

  run('UPDATE sessions SET refresh_token = ?, last_used_at = ? WHERE id = ?', [
    newRefreshToken,
    now,
    session.id,
  ]);

  return { sessionId: session.id, userId: session.user_id, newRefreshToken };
}

export function revokeSession(sessionId, reason = 'user_logout', actorId = null) {
  const session = queryOne('SELECT * FROM sessions WHERE id = ?', [sessionId]);
  if (!session) return false;
  run("UPDATE sessions SET revoked = 1, revoked_reason = ? WHERE id = ?", [reason, sessionId]);
  appendAudit({
    user_id: session.user_id,
    actor: actorId ? (actorId === session.user_id ? 'user' : 'admin') : 'user',
    action: 'SESSION.REVOKED',
    target: sessionId,
    meta: { reason },
  });
  return true;
}

export function revokeAllSessionsForUser(userId, reason = 'security_reset', actor = 'system') {
  run("UPDATE sessions SET revoked = 1, revoked_reason = ? WHERE user_id = ?", [reason, userId]);
  appendAudit({
    user_id: userId,
    actor,
    action: 'SESSION.ALL_REVOKED',
    meta: { reason },
  });
}

// Token Issuance (Access Token & Adaptive Step-up Token)
export function signAccessToken(user, { sessionId = null, serviceId = null } = {}) {
  // If serviceId is specified, generate pairwise subject!
  const subject = serviceId ? generatePairwiseId(user.id, serviceId) : user.id;

  const payload = {
    sub: subject,
    raw_sub: user.id, // retained for internal verify
    role: user.role,
    name: user.name,
    email: user.email,
    roll_number: user.roll_number,
    sid: sessionId,
    iss: 'https://campusgate.university.edu',
    aud: serviceId || 'campus-portal',
  };

  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TTL_SECONDS });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

// FR-2.4: Adaptive step-up token for high-risk actions (fee payment, credential modification)
export function signStepUpToken(userId, purpose) {
  return jwt.sign(
    {
      sub: userId,
      step_up: true,
      purpose,
      auth_time: Math.floor(nowMs() / 1000),
    },
    JWT_SECRET,
    { expiresIn: STEP_UP_TTL_SECONDS }
  );
}

export function verifyStepUpToken(token, expectedPurpose) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.step_up) return false;
    if (expectedPurpose && decoded.purpose !== expectedPurpose) return false;
    return decoded;
  } catch {
    return false;
  }
}

// Impossible Travel Anomaly Detection (FR-7.5)
export function detectImpossibleTravel(user, newLocation, newIp) {
  if (!user.last_login_at || !user.last_login_location) return false;
  const timeDiffMinutes = (nowMs() - user.last_login_at) / (1000 * 60);

  // If previous login was campus/India and next is New York within 10 minutes
  const isPreviousLocal = user.last_login_location.includes('Campus') || user.last_login_location.includes('India') || user.last_login_location.includes('Mumbai');
  const isNewForeign = newLocation.includes('New York') || newLocation.includes('London') || newLocation.includes('Tokyo');

  if (isPreviousLocal && isNewForeign && timeDiffMinutes < 60) {
    const alertId = uid();
    run(
      `INSERT INTO anomaly_alerts (id, user_id, severity, anomaly_type, description, ip, status, created_at)
       VALUES (?, ?, 'CRITICAL', 'IMPOSSIBLE_TRAVEL', ?, ?, 'OPEN', ?)`,
      [
        alertId,
        user.id,
        `Impossible travel detected: Login from ${newLocation} just ${Math.round(timeDiffMinutes)}m after session in ${user.last_login_location}.`,
        newIp,
        nowMs(),
      ]
    );

    appendAudit({
      user_id: user.id,
      actor: 'security_monitor',
      action: 'ANOMALY.IMPOSSIBLE_TRAVEL',
      ip: newIp,
      meta: { previousLocation: user.last_login_location, newLocation, deltaMinutes: Math.round(timeDiffMinutes) },
    });
    return true;
  }
  return false;
}

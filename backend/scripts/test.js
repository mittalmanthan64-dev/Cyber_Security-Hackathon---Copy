// CampusGate — Automated End-to-End PRD Verification Suite
import { seed } from './seed.js';
import {
  db,
  queryOne,
  queryAll,
  verifyAuditChain,
  tamperAuditLogEntry,
  restoreTamperedAuditLog,
  generatePairwiseId,
} from '../db.js';
import {
  verifyPassword,
  totpCurrentToken,
  totpCheck,
  createSession,
  rotateRefreshToken,
  signAccessToken,
  verifyAccessToken,
  signStepUpToken,
  verifyStepUpToken,
  consumeBackupCode,
  isLocked,
  bumpFailedLogin,
  resetFailedLogins,
} from '../auth.js';

let passedCount = 0;
let failedCount = 0;

function assert(condition, testName) {
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passedCount++;
  } else {
    console.error(`  ✗ FAIL: ${testName}`);
    failedCount++;
  }
}

async function runTestSuite() {
  console.log('\n======================================================');
  console.log('🧪 RUNNING CAMPUSGATE PRD ACCEPTANCE TEST SUITE');
  console.log('======================================================\n');

  console.log('Step 0: Seeding database...');
  await seed();

  // Test Suite 1: Authentication & Brute-Force Lockout (FR-2.1, FR-2.3, FR-2.5)
  console.log('\n--- SUITE 1: STRONG AUTHENTICATION & BRUTE-FORCE PROTECTION ---');
  const student = queryOne('SELECT * FROM users WHERE roll_number = ?', ['CS2024001']);
  assert(student !== null, 'Student Aanya Sharma exists in user store');

  const validPw = await verifyPassword(student.password_hash, 'Password@123');
  assert(validPw === true, 'Argon2id password verification succeeds with correct credentials');

  const invalidPw = await verifyPassword(student.password_hash, 'WrongPassword');
  assert(invalidPw === false, 'Argon2id password verification fails with incorrect credentials');

  const currentCode = totpCurrentToken(student.totp_secret);
  const mfaValid = totpCheck(student.totp_secret, currentCode);
  assert(mfaValid === true, 'TOTP 6-digit MFA verification succeeds with current token');

  // Test lockout after 5 failures
  let lockRes;
  for (let i = 0; i < 5; i++) {
    lockRes = bumpFailedLogin(student, '10.20.4.15');
  }
  assert(lockRes.isLocked === true, 'Account locked after 5 consecutive failed logins (FR-2.5)');
  resetFailedLogins(student.id);
  const unlocked = queryOne('SELECT failed_logins, locked_until FROM users WHERE id = ?', [student.id]);
  assert(unlocked.failed_logins === 0, 'Reset failed logins clears lockout upon successful auth');

  // Test Suite 2: Session Management & Replay Reuse Detection (FR-6.1 - FR-6.4)
  console.log('\n--- SUITE 2: SESSIONS & REPLAY ATTACK DEFENSE ---');
  const session = createSession(student, { deviceLabel: 'Chrome on macOS', ip: '10.20.4.15', location: 'Campus Wi-Fi' });
  assert(session.sessionId !== null && session.refreshToken !== null, 'Session created with rotating refresh token');

  const rotated = rotateRefreshToken(session.refreshToken, { ip: '10.20.4.15' });
  assert(rotated.newRefreshToken !== session.refreshToken, 'Refresh token rotated with fresh secret');

  // Replay Attack Test: Attempt to reuse the OLD refresh token!
  let replayBlocked = false;
  try {
    rotateRefreshToken(session.refreshToken, { ip: '198.51.100.99 (Attacker Botnet)' });
  } catch (err) {
    if (err.message.includes('SECURITY_ALERT_TOKEN_REUSE')) {
      replayBlocked = true;
    }
  }
  assert(replayBlocked === true, 'Replay attack blocked: Re-submitting consumed refresh token was rejected!');

  const revokedSessions = queryAll('SELECT revoked FROM sessions WHERE user_id = ? AND revoked = 1', [student.id]);
  assert(revokedSessions.length > 0, 'Replay attack mitigation: All user sessions immediately invalidated!');

  // Test Suite 3: Minimal Data Sharing & Pairwise Unlinkability (FR-5.1 - FR-5.5)
  console.log('\n--- SUITE 3: MINIMAL DATA SHARING & PAIRWISE UNLINKABILITY ---');
  const libPairwise = generatePairwiseId(student.id, 'library');
  const hostelPairwise = generatePairwiseId(student.id, 'hostel');
  const examPairwise = generatePairwiseId(student.id, 'exam-fees');

  assert(libPairwise.startsWith('lib-'), 'Library pairwise identifier has service prefix');
  assert(hostelPairwise.startsWith('hos-'), 'Hostel pairwise identifier has service prefix');
  assert(libPairwise !== hostelPairwise, 'Library and Hostel pairwise IDs are distinct and unlinkable (FR-5.5)');
  assert(hostelPairwise !== examPairwise, 'Hostel and Exam pairwise IDs are distinct and unlinkable (FR-5.5)');

  // Test Suite 4: Adaptive Step-Up Authentication (FR-2.4)
  console.log('\n--- SUITE 4: ADAPTIVE STEP-UP AUTHENTICATION ---');
  const stepUpToken = signStepUpToken(student.id, 'PAY_FEES');
  const decodedStepUp = verifyStepUpToken(stepUpToken, 'PAY_FEES');
  assert(decodedStepUp.step_up === true && decodedStepUp.purpose === 'PAY_FEES', 'Adaptive step-up token signed and verified');

  const invalidPurpose = verifyStepUpToken(stepUpToken, 'CHANGE_PASSWORD');
  assert(invalidPurpose === false, 'Step-up token rejected when used for unverified purpose');

  // Test Suite 5: Tamper-Evident Cryptographic Audit Logging (FR-7.1 - FR-7.3)
  console.log('\n--- SUITE 5: CRYPTOGRAPHIC AUDIT LOG & TAMPER DETECTION ---');
  const initialChain = verifyAuditChain();
  assert(initialChain.valid === true, `Cryptographic audit hash chain verified 100% intact (${initialChain.totalChecked} blocks)`);

  // Deliberate Tamper
  tamperAuditLogEntry(2, 'AUTH.DELIBERATE_TAMPER_ACTION');
  const tamperedChain = verifyAuditChain();
  assert(tamperedChain.valid === false, 'Tamper detected: Audit verification flags altered database block');
  assert(tamperedChain.brokenAtSeq === 2, 'Tamper detected at exact corrupted block sequence #2');

  // Restore
  restoreTamperedAuditLog();
  const restoredChain = verifyAuditChain();
  assert(restoredChain.valid === true, 'Audit chain integrity restored after reverting tamper');

  // Test Suite 6: One-Time Backup Codes & Recovery (FR-8.1 - FR-8.4)
  console.log('\n--- SUITE 6: SELF-SERVE RECOVERY & BACKUP CODES ---');
  const freshStudent = queryOne('SELECT * FROM users WHERE id = ?', [student.id]);
  const codeConsumed = consumeBackupCode(freshStudent, 'CAMP-BK01');
  assert(codeConsumed === true, 'One-time backup code CAMP-BK01 successfully consumed');

  const reuseCode = consumeBackupCode(freshStudent, 'CAMP-BK01');
  assert(reuseCode === false, 'Previously consumed backup code cannot be used again');

  console.log('\n======================================================');
  console.log(`TEST RESULTS: ${passedCount} PASSED, ${failedCount} FAILED`);
  console.log('======================================================\n');

  if (failedCount > 0) {
    process.exit(1);
  }
}

runTestSuite().catch((err) => {
  console.error('Test suite uncaught error:', err);
  process.exit(1);
});

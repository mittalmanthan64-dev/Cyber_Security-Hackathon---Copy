// CampusGate — Database Seeding Script
import { db, uid, nowMs, appendAudit, generatePairwiseId } from '../db.js';
import { migrate } from './migrate.js';
import { hashPassword, generateTotpSecret, generateBackupCodes } from '../auth.js';

export async function seed() {
  migrate();

  const now = nowMs();
  const sixMonths = now + 180 * 24 * 60 * 60 * 1000;

  console.log('Clearing existing data...');
  db.exec('DELETE FROM demo_fee_invoices');
  db.exec('DELETE FROM demo_library_loans');
  db.exec('DELETE FROM anomaly_alerts');
  db.exec('DELETE FROM recovery_events');
  db.exec('DELETE FROM audit_log');
  db.exec('DELETE FROM sessions');
  db.exec('DELETE FROM used_refresh_tokens');
  db.exec('DELETE FROM consents');
  db.exec('DELETE FROM users');
  db.exec('DELETE FROM services');

  console.log('Seeding campus services...');
  const services = [
    {
      id: 'library',
      name: 'Campus Central Library',
      description: 'Book checkouts, academic catalog, reserve collections.',
      icon: 'library',
      required_claims: ['pairwise_id', 'name', 'is_enrolled'],
      purpose: 'Verify active student/faculty enrollment to grant borrowing privileges and digital book reservations.',
    },
    {
      id: 'hostel',
      name: 'Hostel & Housing Portal',
      description: 'Hostel room allocations, wing access control, nightly gate passes.',
      icon: 'home',
      required_claims: ['pairwise_id', 'is_active_resident', 'hostel_block', 'room_no', 'tenancy_valid_until'],
      purpose: 'Verify active resident status and room wing assignment for campus housing access.',
    },
    {
      id: 'exam-fees',
      name: 'Examination & Fee Portal',
      description: 'Semester tuition fees, exam seating passes, transcripts.',
      icon: 'credit-card',
      required_claims: ['pairwise_id', 'program', 'year', 'fee_cleared'],
      purpose: 'Authenticate student program details and verify tuition payment status for exam eligibility.',
    },
  ];

  const insertService = db.prepare(
    `INSERT INTO services (id, name, description, icon, required_claims, purpose, status, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?)`
  );

  for (const s of services) {
    insertService.run(s.id, s.name, s.description, s.icon, JSON.stringify(s.required_claims), s.purpose, now);
  }

  console.log('Seeding initial users...');
  const studentPw = await hashPassword('Password@123');
  const facultyPw = await hashPassword('Faculty@123');
  const adminPw = await hashPassword('Admin@123');
  const libAdminPw = await hashPassword('Librarian@123');

  const studentTotp = generateTotpSecret();
  const studentCodes = generateBackupCodes(8, [
    'CAMP-BK01', 'CAMP-BK02', 'CAMP-BK03', 'CAMP-BK04',
    'CAMP-BK05', 'CAMP-BK06', 'CAMP-BK07', 'CAMP-BK08'
  ]);

  const facultyTotp = generateTotpSecret();
  const facultyCodes = generateBackupCodes(8);

  const adminTotp = generateTotpSecret();
  const adminCodes = generateBackupCodes(8);

  const libTotp = generateTotpSecret();
  const libCodes = generateBackupCodes(8);

  const studentId = uid();
  const facultyId = uid();
  const adminId = uid();
  const libAdminId = uid();
  const pendingStudentId = uid();

  const insertUser = db.prepare(
    `INSERT INTO users
      (id, roll_number, name, email, phone, role, program, year, hostel_block, room_no,
       is_enrolled, is_active_resident, tenancy_expires_at, fee_status,
       password_hash, totp_secret, totp_enrolled, backup_codes, failed_logins, locked_until,
       status, activation_code, created_at, last_login_at, last_login_location, last_login_ip)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?)`
  );

  // 1. Student Aanya Sharma
  insertUser.run(
    studentId,
    'CS2024001',
    'Aanya Sharma',
    'aanya.sharma@university.edu',
    '+91-98765-43210',
    'student',
    'B.Tech Computer Science',
    '3rd Year',
    'Block-C',
    '304',
    1,
    1,
    sixMonths,
    'PENDING',
    studentPw,
    studentTotp,
    1,
    JSON.stringify(studentCodes.hashedCodes),
    'ACTIVE',
    null,
    now - 15 * 60 * 1000,
    now - 15 * 60 * 1000,
    'Campus Wi-Fi - Academic Quad',
    '10.20.4.15'
  );

  // 2. Faculty Dr. Rohan Mehta
  insertUser.run(
    facultyId,
    'FAC-2024-07',
    'Dr. Rohan Mehta',
    'rohan.mehta@university.edu',
    '+91-98765-12345',
    'faculty',
    'Department of Computing',
    'Professor',
    null,
    null,
    1,
    0,
    null,
    'PAID',
    facultyPw,
    facultyTotp,
    1,
    JSON.stringify(facultyCodes.hashedCodes),
    'ACTIVE',
    null,
    now - 2 * 60 * 60 * 1000,
    now - 2 * 60 * 60 * 1000,
    'Faculty Hall - Ethernet',
    '10.20.1.5'
  );

  // 3. Security Admin Priya Nair
  insertUser.run(
    adminId,
    'ADM-2024-01',
    'Priya Nair',
    'priya.nair@university.edu',
    '+91-98765-67890',
    'admin',
    'Information Security Operations',
    'Chief SecOps',
    null,
    null,
    1,
    0,
    null,
    'PAID',
    adminPw,
    adminTotp,
    1,
    JSON.stringify(adminCodes.hashedCodes),
    'ACTIVE',
    null,
    now - 30 * 60 * 1000,
    now - 30 * 60 * 1000,
    'SecOps SOC Terminal',
    '10.20.0.2'
  );

  // 4. Service Admin Vikram Rao (Librarian)
  insertUser.run(
    libAdminId,
    'LIB-2024-03',
    'Vikram Rao',
    'vikram.rao@university.edu',
    '+91-98765-33445',
    'service_admin',
    'Campus Libraries',
    'Head Librarian',
    null,
    null,
    1,
    0,
    null,
    'PAID',
    libAdminPw,
    libTotp,
    1,
    JSON.stringify(libCodes.hashedCodes),
    'ACTIVE',
    null,
    now - 4 * 60 * 60 * 1000,
    now - 4 * 60 * 60 * 1000,
    'Library Circulation Desk',
    '10.20.8.12'
  );

  // 5. Pending Activation student Kabir Patel (for FR-1.1 demo)
  insertUser.run(
    pendingStudentId,
    'EE2024089',
    'Kabir Patel',
    'kabir.patel@university.edu',
    '+91-98765-99887',
    'student',
    'B.Tech Electrical Eng',
    '1st Year',
    'Block-A',
    '108',
    1,
    1,
    sixMonths,
    'PENDING',
    studentPw, // placeholder until set
    null,
    0,
    '[]',
    'PENDING_ACTIVATION',
    'ACT-CAMPUS-2026',
    now - 24 * 60 * 60 * 1000,
    null,
    null,
    null
  );

  console.log('Seeding pre-consented service for student (Library)...');
  const insertConsent = db.prepare(
    `INSERT INTO consents (id, user_id, service_id, granted_claims, pairwise_id, granted_at, revoked)
     VALUES (?, ?, ?, ?, ?, ?, 0)`
  );

  // Student consented to Library initially, but NOT yet to Hostel or Exam-Fees (to demonstrate SSO consent screen!)
  insertConsent.run(
    uid(),
    studentId,
    'library',
    JSON.stringify(['pairwise_id', 'name', 'is_enrolled']),
    generatePairwiseId(studentId, 'library'),
    now - 10 * 60 * 1000
  );

  console.log('Seeding sample library books and fee invoice...');
  const insertLoan = db.prepare(
    `INSERT INTO demo_library_loans (id, user_id, book_title, isbn, borrowed_at, due_date, returned)
     VALUES (?, ?, ?, ?, ?, ?, 0)`
  );
  insertLoan.run(uid(), studentId, 'Cryptography and Network Security: Principles and Practice', '978-0134444284', now - 5 * 86400000, now + 9 * 86400000);
  insertLoan.run(uid(), studentId, 'Designing Data-Intensive Applications', '978-1449373320', now - 2 * 86400000, now + 12 * 86400000);

  const insertInvoice = db.prepare(
    `INSERT INTO demo_fee_invoices (id, user_id, description, amount, status, paid_at, tx_hash)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  );
  insertInvoice.run(uid(), studentId, 'Spring 2026 Tuition & Laboratory Fee', 1250.0, 'PENDING', null, null);

  console.log('Initializing cryptographic hash-chained audit logs...');
  appendAudit({
    user_id: null,
    actor: 'system',
    action: 'SYSTEM.INITIALIZED',
    target: 'IdP Core',
    ip: '127.0.0.1',
    device: 'Internal Boot',
    meta: { version: '1.0.0', cryptographicChain: 'SHA-256' },
    timestamp: now - 3600000,
  });

  appendAudit({
    user_id: studentId,
    actor: 'user',
    action: 'AUTH.ENROLLMENT_COMPLETED',
    target: 'CS2024001',
    ip: '10.20.4.15',
    device: 'Chrome / Windows',
    meta: { mfa: 'TOTP', backupCodesGenerated: 8 },
    timestamp: now - 1800000,
  });

  appendAudit({
    user_id: studentId,
    actor: 'user',
    action: 'AUTH.LOGIN_SUCCESS',
    target: 'IdP Session',
    ip: '10.20.4.15',
    device: 'Chrome / Windows',
    meta: { mfaVerified: true, method: 'password+totp' },
    timestamp: now - 900000,
  });

  appendAudit({
    user_id: studentId,
    actor: 'user',
    action: 'CONSENT.GRANTED',
    service_id: 'library',
    claim: 'pairwise_id,name,is_enrolled',
    ip: '10.20.4.15',
    device: 'Chrome / Windows',
    meta: { pairwiseId: generatePairwiseId(studentId, 'library') },
    timestamp: now - 600000,
  });

  console.log('\n========================================');
  console.log('✅ CAMPUSGATE DATABASE SUCCESSFULLY SEEDED');
  console.log('========================================');
  console.log('Demo Accounts:');
  console.log('1. Student:       aanya.sharma@university.edu  / Password@123  (Secret: ' + studentTotp + ')');
  console.log('   Plain Backup Codes: ' + studentCodes.plainCodes.slice(0, 4).join(', '));
  console.log('2. Faculty:       rohan.mehta@university.edu   / Faculty@123   (Secret: ' + facultyTotp + ')');
  console.log('3. Admin:         priya.nair@university.edu    / Admin@123     (Secret: ' + adminTotp + ')');
  console.log('4. Service Admin: vikram.rao@university.edu    / Librarian@123 (Secret: ' + libTotp + ')');
  console.log('5. Unactivated:   kabir.patel@university.edu   (Activation Code: ACT-CAMPUS-2026)');
  console.log('========================================\n');
}

if (process.argv[1] && process.argv[1].endsWith('seed.js')) {
  seed().catch(console.error);
}

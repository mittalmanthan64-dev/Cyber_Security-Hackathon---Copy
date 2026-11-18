# CampusGate — Secure Digital Identity Layer for Campus Services

> **Product Requirements Document (PRD v1.0) Reference Implementation**  
> An enterprise-grade, privacy-conscious digital identity and access management (IAM) platform built specifically for campus environments. It demonstrates Single Sign-On (OIDC SSO), strong multi-factor authentication (TOTP + Argon2id), attribute minimization with boolean/derived claims, pairwise pseudonymous identifiers (PPID), tamper-evident cryptographic hash-chained audit logging, adaptive step-up authentication, and resilient self-serve recovery.

---

## 🏛️ System Architecture & PRD Scope Mapping

```
                                  ┌───────────────────────────────┐
                                  │      CampusGate Identity      │
                                  │     Provider Core (IdP)       │
                                  └──────────────┬────────────────┘
                                                 │
                  ┌──────────────────────────────┼──────────────────────────────┐
                  │                              │                              │
                  ▼                              ▼                              ▼
      ┌───────────────────────┐      ┌───────────────────────┐      ┌───────────────────────┐
      │   Campus Library      │      │  Hostel & Housing     │      │  Exam & Fee Portal    │
      │   (Relying Party 1)   │      │   (Relying Party 2)   │      │   (Relying Party 3)   │
      ├───────────────────────┤      ├───────────────────────┤      ├───────────────────────┤
      │ • Pairwise ID: lib-*  │      │ • Pairwise ID: hos-*  │      │ • Pairwise ID: exm-*  │
      │ • is_enrolled: true   │      │ • is_active_resident  │      │ • fee_status: PENDING │
      │ • Role: student/fac   │      │ • time-bound tenancy  │      │ • Adaptive Step-Up    │
      └───────────────────────┘      └───────────────────────┘      └───────────────────────┘
```

| PRD Section | Functional Requirement | CampusGate Implementation |
| :--- | :--- | :--- |
| **6.1 Identity Enrollment** | **FR-1.1 - FR-1.3** | Roster CSV/JSON onboarding, one-time invitation activation codes, immutable internal DID/UUIDs separate from displayed roll numbers. |
| **6.2 Strong Authentication**| **FR-2.1 - FR-2.5** | Argon2id password hashing, TOTP 6-digit MFA (RFC 6238), breached-password checks, progressive delays & 15m lockout after 5 failed logins, adaptive step-up for sensitive actions. |
| **6.3 Single Sign-On (SSO)**| **FR-3.1 - FR-3.3** | OIDC-compliant SSO authorization code & token exchange. Authenticate once, access Library, Hostel, and Exam portals without retyping password. |
| **6.4 Role-Based Access**   | **FR-4.1 - FR-4.4** | Dynamic RBAC (`student`, `faculty`, `staff`, `service_admin`, `admin`). Instant server-side revocation and quota adjustments. Time-bound tenancy enforcement. |
| **6.5 Data Minimization**   | **FR-5.1 - FR-5.5** | Plain-language consent review screens, derived boolean claims (`is_enrolled: true`, `is_active_resident: true`), and pairwise pseudonymous identifiers (PPID) preventing cross-service student tracking (DPDP Act 2023 compliant). |
| **6.6 Secure Sessions**     | **FR-6.1 - FR-6.5** | 15-minute short-lived access tokens, rotating refresh tokens with reuse detection (replay attack defense), active session registry, remote logout, and Global Single Logout (SLO). |
| **6.7 Audit Logging**       | **FR-7.1 - FR-7.5** | Append-only cryptographically chained SHA-256 audit log (`H(n) = SHA256(H(n-1) + block)`). Real-time integrity verifier and live tamper-detection simulation tool. Impossible travel and brute force alerts. |
| **6.8 Recovery Flows**      | **FR-8.1 - FR-8.5** | 8 one-time backup codes shown once and stored hashed, self-service lost device recovery, cooling-off period notification with legitimate user abort button, and universal session revocation. |
| **6.9 Admin Console**       | **FR-9.1 - FR-9.3** | Security Operations Center for instant user role edits, emergency account suspensions, roster onboarding, cryptographic chain verification, and incident response. |

---

## 🚀 Quick Start & Running Locally

### Prerequisites
- Node.js v20+ (tested on Node v26)

### 1. Install Dependencies
```bash
cd backend
npm install
```

### 2. Seed Database
```bash
node backend/scripts/seed.js
```

### 3. Run Automated PRD Test Suite
```bash
node backend/scripts/test.js
```
*(Runs 22 automated end-to-end unit and security assertions verifying all acceptance criteria!)*

### 4. Start the Application
```bash
node backend/server.js
```
Open **`http://localhost:3000`** in any web browser.

---

## 👥 Seeded Demo Accounts

| Role | Name | Email | Password | Seeded Backup Code |
| :--- | :--- | :--- | :--- | :--- |
| **Student** | Aanya Sharma | `aanya.sharma@university.edu` | `Password@123` | `CAMP-BK01` |
| **Faculty** | Dr. Rohan Mehta | `rohan.mehta@university.edu` | `Faculty@123` | `CAMP-BK01` |
| **Security Admin** | Priya Nair | `priya.nair@university.edu` | `Admin@123` | `CAMP-BK01` |
| **Librarian** | Vikram Rao | `vikram.rao@university.edu` | `Librarian@123` | `CAMP-BK01` |
| **Pending Activation** | Kabir Patel | `kabir.patel@university.edu` | *(Set upon activation)* | Code: `ACT-CAMPUS-2026` |

> 💡 **Built-in TOTP Helper:** Click the **TOTP Helper** pill in the top navbar to view the active demo user's current live 6-digit TOTP code and animated countdown bar. You can also copy it with 1 click or use the "⚡ Auto-fill" buttons in any form!

---

## 🧪 PRD Acceptance Criteria Demonstration (Section 11)

Navigate to the **`PRD Acceptance Runner`** tab in the web interface to run and verify all 8 criteria live on screen:

1. **Account Activation & MFA:** Kabir Patel verifies invite code `ACT-CAMPUS-2026`, passes breach list checks, sets password, scans QR code, receives 8 backup codes, and completes enrollment.
2. **Seamless SSO:** Signs into Library (Service A), then opens Hostel Housing (Service B) without re-entering credentials.
3. **Minimal Attributes & Unlinkability:** Demonstrates Library gets `lib-xxxx` with `{ is_enrolled: true }`, while Hostel gets `hos-yyyy` with `{ is_active_resident: true }`. Services cannot cross-correlate student activities.
4. **Dynamic Role Modification:** Security Admin changes Aanya's role to Faculty; the Library borrowing limit expands from 3 to 10 books immediately, and monograph reserve privileges unlock server-side.
5. **Remote Session Revocation:** Student views device registry in the Privacy Dashboard and terminates a remote device session; subsequent requests using that session are rejected.
6. **Token Replay / Reuse Attack Defense:** Simulates an attacker intercepting and replaying an already-consumed refresh token; the IdP immediately invalidates all active sessions for the user and triggers a CRITICAL incident alert.
7. **Tamper-Evident Cryptographic Audit Detection:** Click **"Simulate Tampering Attack"** to forge a record in SQLite; click **"Verify Chain Integrity"** and watch the system pinpoint the exact corrupted block sequence with cryptographic proof!
8. **Lost-Device Recovery:** Student enters backup code `CAMP-BK01`, enters cooling-off period, re-enrolls MFA, and all pre-existing sessions across all devices are immediately terminated.

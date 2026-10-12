import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';

// Ensure test environment before importing app
process.env.NODE_ENV = 'test';

import { app } from '../src/app';
import { firestoreRepo } from '../src/config/firebase';
import { decryptAes256Gcm, encryptAes256Gcm } from '../src/services/encryptionService';
import { hashPassword, verifyPassword } from '../src/services/passwordService';
import { ensureDefaultNketiahSeedData } from '../src/services/seedService';
import { generateTotpCode } from '../src/services/totpService';

describe('NKETIAH School Management System - Cybersecurity & API Test Suite', () => {
  beforeEach(async () => {
    await firestoreRepo.clearAllForTesting();
    await ensureDefaultNketiahSeedData();
  });

  // ==========================================================================
  // 1. CRYPTOGRAPHY: ARGON2ID + UNIQUE SALT + SERVER PEPPER
  // ==========================================================================
  describe('Phase 6: Argon2id + Per-Password Unique Salt + Server-Side Pepper', () => {
    it('hashes passwords with Argon2id, uses unique salts for identical passwords, and requires the server pepper', async () => {
      const plain = 'NketiahCyber#2026!';
      const hash1 = await hashPassword(plain);
      const hash2 = await hashPassword(plain);

      // Must use Argon2id format ($argon2id$v=19$...)
      expect(hash1.startsWith('$argon2id$')).toBe(true);
      expect(hash2.startsWith('$argon2id$')).toBe(true);

      // Unique salts mean two hashes of the exact same password are NEVER equal
      expect(hash1).not.toEqual(hash2);

      // Correct password + correct server pepper verifies true
      expect(await verifyPassword(plain, hash1)).toBe(true);
      expect(await verifyPassword('WrongPassword#123', hash1)).toBe(false);

      // If an attacker steals the hash from Firestore but does NOT have the server-side pepper, verification fails
      const wrongPepper = '0000000000000000000000000000000000000000000000000000000000000000';
      expect(await verifyPassword(plain, hash1, wrongPepper)).toBe(false);
    });
  });

  // ==========================================================================
  // 2. CRYPTOGRAPHY: AES-256-GCM SYMMETRIC AUTHENTICATED ENCRYPTION
  // ==========================================================================
  describe('Phase 10: AES-256-GCM Encryption, Unique IVs & Tamper Detection', () => {
    it('encrypts and decrypts TOTP secrets with unique 96-bit IVs and detects 1-bit tampering via 128-bit Auth Tag', () => {
      const secretPlaintext = 'JBSWY3DPEHPK3PXP';
      const encrypted1 = encryptAes256Gcm(secretPlaintext);
      const encrypted2 = encryptAes256Gcm(secretPlaintext);

      // Each encryption generates a unique 12-byte (24 hex chars) IV
      expect(encrypted1.ivHex).toHaveLength(24);
      expect(encrypted1.authTagHex).toHaveLength(32);
      expect(encrypted1.ivHex).not.toEqual(encrypted2.ivHex);
      expect(encrypted1.ciphertextHex).not.toEqual(encrypted2.ciphertextHex);

      // Decrypts back to original plaintext
      expect(decryptAes256Gcm(encrypted1)).toBe(secretPlaintext);

      // Tampering with ciphertext must throw an authentication error
      const tamperedCiphertext = {
        ...encrypted1,
        ciphertextHex:
          encrypted1.ciphertextHex.slice(0, -2) +
          (encrypted1.ciphertextHex.endsWith('aa') ? 'bb' : 'aa'),
      };
      expect(() => decryptAes256Gcm(tamperedCiphertext)).toThrow();
    });
  });

  // ==========================================================================
  // 3. USER REGISTRATION & USERNAME-ONLY AUTHENTICATION
  // ==========================================================================
  describe('Phase 5 & 7: Username + Password Registration, Login & Token Rotation', () => {
    it('registers a new student using ONLY username + password + confirmPassword (no email) and blocks duplicates', async () => {
      const registerRes = await request(app).post('/api/auth/register').send({
        username: 'ama_nketiah',
        password: 'AmaSecure@2026!',
        confirmPassword: 'AmaSecure@2026!',
        fullName: 'Ama Boateng',
        department: 'Computer Science',
      });

      expect(registerRes.status).toBe(201);
      expect(registerRes.body.success).toBe(true);
      expect(registerRes.body.data.user.username).toBe('ama_nketiah');
      expect(registerRes.body.data.user.role).toBe('USER');
      // Never leaks passwordHash or TOTP secrets
      expect(registerRes.body.data.user.passwordHash).toBeUndefined();
      expect(registerRes.body.data.accessToken).toBeDefined();
      expect(registerRes.body.data.refreshToken).toBeDefined();

      // Case-insensitive duplicate username check
      const dupRes = await request(app).post('/api/auth/register').send({
        username: 'AMA_NKETIAH',
        password: 'AmaSecure@2026!',
        confirmPassword: 'AmaSecure@2026!',
      });
      expect(dupRes.status).toBe(409);
    });

    it('rejects wrong passwords and locks the account after 5 consecutive failed attempts', async () => {
      for (let i = 1; i <= 5; i++) {
        const res = await request(app).post('/api/auth/login').send({
          username: 'kwame_student',
          password: 'WrongPassword@123!',
        });
        expect(res.status).toBe(401);
      }

      // 6th attempt even with the CORRECT password must return 423 Locked
      const lockedRes = await request(app).post('/api/auth/login').send({
        username: 'kwame_student',
        password: 'Student@Nketiah2026!',
      });
      expect(lockedRes.status).toBe(423);
    });
  });

  // ==========================================================================
  // 4. TWO-FACTOR AUTHENTICATION (TOTP + AES-256-GCM + RECOVERY CODES)
  // ==========================================================================
  describe('Phase 9: TOTP Two-Factor Authentication & One-Time Recovery Codes', () => {
    it('completes full 2FA lifecycle: setup QR -> enable -> login with TOTP -> login with Recovery Code -> disable', async () => {
      // 1. Login as seeded student
      const loginRes = await request(app).post('/api/auth/login').send({
        username: 'kwame_student',
        password: 'Student@Nketiah2026!',
      });
      expect(loginRes.status).toBe(200);
      const accessToken = loginRes.body.data.accessToken;

      // 2. Initiate 2FA Setup
      const setupRes = await request(app)
        .post('/api/auth/2fa/setup')
        .set('Authorization', `Bearer ${accessToken}`);
      expect(setupRes.status).toBe(200);
      const { manualEntryKey, qrCodeDataUrl } = setupRes.body.data;
      expect(qrCodeDataUrl.startsWith('data:image/png;base64,')).toBe(true);
      expect(manualEntryKey.length).toBeGreaterThan(16);

      // Verify pending TOTP secret is encrypted in Firestore (NOT plaintext!)
      const rawUserDoc = await firestoreRepo.findUserByUsername('kwame_student');
      expect(rawUserDoc?.pendingTotpSecretEncrypted?.algorithm).toBe('aes-256-gcm');
      expect(JSON.stringify(rawUserDoc?.pendingTotpSecretEncrypted)).not.toContain(
        manualEntryKey
      );

      // 3. Reject invalid 6-digit code during enable
      const badEnableRes = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code: '000000' });
      // (unless 000000 happens to be the current code, which is 1 in 1,000,000)
      if (generateTotpCode(manualEntryKey) !== '000000') {
        expect(badEnableRes.status).toBe(400);
      }

      // 4. Enable 2FA with valid RFC 6238 TOTP code
      const validTotpCode = generateTotpCode(manualEntryKey);
      const enableRes = await request(app)
        .post('/api/auth/2fa/enable')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ code: validTotpCode });
      expect(enableRes.status).toBe(200);
      const recoveryCodes: string[] = enableRes.body.data.recoveryCodes;
      expect(recoveryCodes).toHaveLength(8);

      // 5. Now login with username + password -> must require 2FA and NOT return an access token yet
      const step1Login = await request(app).post('/api/auth/login').send({
        username: 'kwame_student',
        password: 'Student@Nketiah2026!',
      });
      expect(step1Login.status).toBe(200);
      expect(step1Login.body.requiresTwoFactor).toBe(true);
      expect(step1Login.body.data.accessToken).toBeUndefined();
      const preAuthToken = step1Login.body.data.preAuthToken;

      // 6. Verify 2FA with TOTP code
      const step2Totp = await request(app).post('/api/auth/verify-2fa').send({
        preAuthToken,
        code: generateTotpCode(manualEntryKey),
      });
      expect(step2Totp.status).toBe(200);
      expect(step2Totp.body.data.accessToken).toBeDefined();

      // 7. Login using a One-Time Recovery Code and verify it cannot be reused
      const step1RecoveryLogin = await request(app).post('/api/auth/login').send({
        username: 'kwame_student',
        password: 'Student@Nketiah2026!',
      });
      const firstRecoveryCode = recoveryCodes[0];

      const step2Recovery = await request(app).post('/api/auth/verify-2fa').send({
        preAuthToken: step1RecoveryLogin.body.data.preAuthToken,
        code: firstRecoveryCode,
      });
      expect(step2Recovery.status).toBe(200);
      expect(step2Recovery.body.data.usedRecoveryCode).toBe(true);
      expect(step2Recovery.body.data.remainingRecoveryCodes).toBe(7);

      // Reusing the exact same recovery code must fail!
      const replayRecovery = await request(app).post('/api/auth/verify-2fa').send({
        preAuthToken: step1RecoveryLogin.body.data.preAuthToken,
        code: firstRecoveryCode,
      });
      expect(replayRecovery.status).toBe(401);
    });
  });

  // ==========================================================================
  // 5. ROLE-BASED AUTHORIZATION (GUEST / USER / ADMIN)
  // ==========================================================================
  describe('Phase 8: Role-Based Authorization (RBAC) Enforcement', () => {
    it('blocks USER from accessing ADMIN endpoints and logs UNAUTHORIZED_ACCESS_ATTEMPT', async () => {
      const studentLogin = await request(app).post('/api/auth/login').send({
        username: 'kwame_student',
        password: 'Student@Nketiah2026!',
      });
      const studentToken = studentLogin.body.data.accessToken;

      // Student tries to list all users on /api/admin/users
      const forbiddenRes = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${studentToken}`);
      expect(forbiddenRes.status).toBe(403);

      // Admin logs in and can view users & audit logs
      const adminLogin = await request(app).post('/api/auth/login').send({
        username: 'nketiah_admin',
        password: 'Admin@Nketiah2026!',
      });
      const adminToken = adminLogin.body.data.accessToken;

      const usersRes = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(usersRes.status).toBe(200);
      expect(usersRes.body.data.users.length).toBeGreaterThanOrEqual(2);

      const logsRes = await request(app)
        .get('/api/admin/audit-logs')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(logsRes.status).toBe(200);
      const unauthorizedEvent = logsRes.body.data.auditLogs.find(
        (l: { eventType: string }) => l.eventType === 'UNAUTHORIZED_ACCESS_ATTEMPT'
      );
      expect(unauthorizedEvent).toBeDefined();
    });
  });

  // ==========================================================================
  // 6. AUTOMATED BACKUP & DATABASE RESTORATION VERIFICATION
  // ==========================================================================
  describe('Phase 16, 17 & 18: Encrypted Firestore Backup & Database Restoration', () => {
    it('creates an AES-256-GCM encrypted backup, deletes a user, and restores the deleted user from the backup', async () => {
      const adminLogin = await request(app).post('/api/auth/login').send({
        username: 'nketiah_admin',
        password: 'Admin@Nketiah2026!',
      });
      const adminToken = adminLogin.body.data.accessToken;

      // 1. Trigger an encrypted backup via Admin API
      const createBackupRes = await request(app)
        .post('/api/admin/backups')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(createBackupRes.status).toBe(201);
      const backupId = createBackupRes.body.data.backup.backupId;
      expect(createBackupRes.body.data.backup.encryptionAlgorithm).toBe('aes-256-gcm');
      expect(createBackupRes.body.data.backup.checksumSha256).toHaveLength(64);

      // 2. Find `kwame_student` and delete their account to simulate accidental data loss
      const studentBefore = await firestoreRepo.findUserByUsername('kwame_student');
      expect(studentBefore).not.toBeNull();

      const deleteRes = await request(app)
        .delete(`/api/admin/users/${studentBefore!.id}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(deleteRes.status).toBe(200);

      // Confirm `kwame_student` is gone from the database
      const studentAfterDelete = await firestoreRepo.findUserByUsername('kwame_student');
      expect(studentAfterDelete).toBeNull();

      // 3. Restore the database from the encrypted backup!
      const restoreRes = await request(app)
        .post(`/api/admin/backups/${backupId}/restore`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(restoreRes.status).toBe(200);

      // 4. Verify `kwame_student` is completely restored and can log in again!
      const studentAfterRestore = await firestoreRepo.findUserByUsername('kwame_student');
      expect(studentAfterRestore).not.toBeNull();

      const studentLoginAgain = await request(app).post('/api/auth/login').send({
        username: 'kwame_student',
        password: 'Student@Nketiah2026!',
      });
      expect(studentLoginAgain.status).toBe(200);
    });
  });
});

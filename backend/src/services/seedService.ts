import crypto from 'crypto';
import { firestoreRepo } from '../config/firebase';
import { recordAuditLog } from './auditService';
import { createDatabaseBackup, listBackupLogs } from './backupService';
import { hashPassword } from './passwordService';
import { SchoolNoticeDocument, UserDocument } from '../types/models';

/**
 * Seeds default NKETIAH School accounts and notices if the database is empty.
 * - Admin:   `nketiah_admin` / `Admin@Nketiah2026!`
 * - Student: `kwame_student` / `Student@Nketiah2026!`
 */
export async function ensureDefaultNketiahSeedData(): Promise<void> {
  const existingUsers = await firestoreRepo.listDocs('users');
  if (existingUsers.length > 0) {
    const nketiahUser = await firestoreRepo.findUserByUsername('Nketiah');
    if (nketiahUser) {
      const updatedHash = await hashPassword('Nketiah123$$$');
      await firestoreRepo.updateDoc('users', nketiahUser.id, {
        passwordHash: updatedHash,
        failedLoginAttempts: 0,
        lockoutUntil: null,
        status: 'ACTIVE',
      });
    }
    return;
  }

  const now = new Date().toISOString();

  // 1. Seed Default NKETIAH Administrator
  const adminId = `usr_admin_${crypto.randomBytes(6).toString('hex')}`;
  const adminPasswordHash = await hashPassword('Admin@Nketiah2026!');

  const adminUser: UserDocument = {
    id: adminId,
    username: 'nketiah_admin',
    usernameNormalized: 'nketiah_admin',
    fullName: 'Dr. Kofi Nketiah (Chief Security Administrator)',
    department: 'School Administration & Cybersecurity',
    studentOrStaffId: 'NK-ADM-2026-0001',
    role: 'ADMIN',
    status: 'ACTIVE',
    passwordHash: adminPasswordHash,
    twoFactorEnabled: false,
    totpSecretEncrypted: null,
    pendingTotpSecretEncrypted: null,
    failedLoginAttempts: 0,
    lockoutUntil: null,
    lastLoginAt: now,
    createdAt: now,
    updatedAt: now,
  };

  await firestoreRepo.setDoc('users', adminId, adminUser);

  // 2. Seed Default NKETIAH Student / User Account
  const studentId = `usr_stu_${crypto.randomBytes(6).toString('hex')}`;
  const studentPasswordHash = await hashPassword('Student@Nketiah2026!');

  const studentUser: UserDocument = {
    id: studentId,
    username: 'kwame_student',
    usernameNormalized: 'kwame_student',
    fullName: 'Kwame Mensah (BSc Information Technology)',
    department: 'Information Technology',
    studentOrStaffId: 'NK-STU-2026-1042',
    role: 'USER',
    status: 'ACTIVE',
    passwordHash: studentPasswordHash,
    twoFactorEnabled: false,
    totpSecretEncrypted: null,
    pendingTotpSecretEncrypted: null,
    failedLoginAttempts: 0,
    lockoutUntil: null,
    lastLoginAt: now,
    createdAt: now,
    updatedAt: now,
  };

  await firestoreRepo.setDoc('users', studentId, studentUser);

  // 3. Seed NKETIAH School Notices across all 3 visibility tiers (PUBLIC, AUTHENTICATED_ONLY, ADMIN_ONLY)
  const notices: SchoolNoticeDocument[] = [
    {
      id: 'ntc_public_welcome',
      title: 'Welcome to NKETIAH School Management System (2026/2027)',
      category: 'GENERAL',
      content:
        'Welcome to the official NKETIAH School Portal. All students and staff authenticate strictly with their unique Username, Password, and TOTP Two-Factor Authentication (2FA). No email address is required.',
      visibility: 'PUBLIC',
      authorUsername: 'nketiah_admin',
      authorRole: 'ADMIN',
      createdAt: now,
      updatedAt: now,
    },
    {
      id: 'ntc_public_admissions',
      title: 'Department of Information Technology Academic Calendar',
      category: 'ACADEMIC',
      content:
        'Mid-semester cybersecurity laboratory assessments and cryptographic project demonstrations begin this month. Ensure your student portal account is active.',
      visibility: 'PUBLIC',
      authorUsername: 'nketiah_admin',
      authorRole: 'ADMIN',
      createdAt: now,
      updatedAt: now,
    },
    {
      id: 'ntc_user_security_policy',
      title: 'Mandatory 2FA Security Policy for NKETIAH Students & Staff',
      category: 'SECURITY',
      content:
        'All authenticated NKETIAH students and staff are strongly encouraged to enable TOTP Two-Factor Authentication under Security Settings using Google Authenticator or Microsoft Authenticator.',
      visibility: 'AUTHENTICATED_ONLY',
      authorUsername: 'nketiah_admin',
      authorRole: 'ADMIN',
      createdAt: now,
      updatedAt: now,
    },
    {
      id: 'ntc_admin_backup_directive',
      title: 'CONFIDENTIAL: Automated Firestore Backup & Encryption Protocol',
      category: 'SECURITY',
      content:
        'Admin Directive: All Firestore collections are backed up automatically on a 6-hour schedule and encrypted at rest using AES-256-GCM with SHA-256 integrity verification.',
      visibility: 'ADMIN_ONLY',
      authorUsername: 'nketiah_admin',
      authorRole: 'ADMIN',
      createdAt: now,
      updatedAt: now,
    },
  ];

  for (const notice of notices) {
    await firestoreRepo.setDoc('schoolNotices', notice.id, notice);
  }

  await recordAuditLog({
    eventType: 'REGISTER_SUCCESS',
    severity: 'INFO',
    actorUsername: 'SYSTEM_SEEDER',
    details:
      'Initialized default NKETIAH accounts (nketiah_admin [ADMIN], kwame_student [USER]) and school notices.',
  });

  const existingBackups = await listBackupLogs();
  if (existingBackups.length === 0) {
    await createDatabaseBackup({
      triggerType: 'AUTOMATED_CRON',
      triggeredByUsername: 'INITIAL_SYSTEM_SNAPSHOT',
    });
  }
}

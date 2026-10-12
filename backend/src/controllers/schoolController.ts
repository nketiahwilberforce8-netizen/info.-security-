import crypto from 'crypto';
import { Request, Response } from 'express';
import { env } from '../config/env';
import { firestoreRepo } from '../config/firebase';
import { recordAuditLog } from '../services/auditService';
import { verifyAccessToken } from '../services/tokenService';
import { SchoolNoticeDocument, UserRole } from '../types/models';
import { createSchoolNoticeSchema } from '../utils/validators';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - SCHOOL PORTAL & NOTICES CONTROLLER
 * ============================================================================
 *
 * Demonstrates Role-Based Visibility across GUEST, USER, and ADMIN roles:
 * - GUEST: Sees PUBLIC notices and public school portal overview.
 * - USER : Sees PUBLIC + AUTHENTICATED_ONLY student/staff notices.
 * - ADMIN: Sees PUBLIC + AUTHENTICATED_ONLY + ADMIN_ONLY notices, and can create/delete notices.
 */

function resolveCallerRole(req: Request): UserRole {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return 'GUEST';
    const token = authHeader.slice(7).trim();
    const decoded = verifyAccessToken(token);
    return decoded.role || 'GUEST';
  } catch {
    return 'GUEST';
  }
}

export async function getPublicSchoolOverviewHandler(req: Request, res: Response): Promise<void> {
  const callerRole = resolveCallerRole(req);
  const allNotices = await firestoreRepo.listDocs('schoolNotices');

  const visibleNotices = allNotices
    .filter((n) => {
      if (callerRole === 'ADMIN') return true;
      if (callerRole === 'USER') return n.visibility !== 'ADMIN_ONLY';
      return n.visibility === 'PUBLIC';
    })
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

  res.status(200).json({
    success: true,
    data: {
      schoolName: env.SCHOOL_NAME,
      motto: 'Excellence in Technology, Integrity in Cybersecurity',
      academicYear: '2026 / 2027 Academic Session',
      callerRole,
      securityArchitecture: {
        authentication: 'Username + Password (No Email Required) + RFC 6238 TOTP 2FA',
        passwordHashing: 'Argon2id + 128-bit Unique Salt + 256-bit Server-Side Pepper',
        cryptography: 'AES-256-GCM Authenticated Encryption (96-bit IV + 128-bit Auth Tag)',
        authorization: 'Role-Based Access Control (GUEST, USER, ADMIN)',
        database: 'Google Cloud / Firebase Firestore + Encrypted Automated Backups',
      },
      notices: visibleNotices,
    },
  });
}

export async function createSchoolNoticeHandler(req: Request, res: Response): Promise<void> {
  const parsed = createSchoolNoticeSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      success: false,
      error: parsed.error.issues[0]?.message || 'Invalid notice payload.',
    });
    return;
  }

  const adminUser = req.authUser!;
  const now = new Date().toISOString();
  const id = `ntc_${crypto.randomUUID()}`;

  const notice: SchoolNoticeDocument = {
    id,
    title: parsed.data.title,
    category: parsed.data.category,
    content: parsed.data.content,
    visibility: parsed.data.visibility,
    authorUsername: adminUser.username,
    authorRole: adminUser.role,
    createdAt: now,
    updatedAt: now,
  };

  await firestoreRepo.setDoc('schoolNotices', id, notice);

  await recordAuditLog({
    eventType: 'SCHOOL_NOTICE_CREATED',
    severity: 'INFO',
    actorUserId: adminUser.id,
    actorUsername: adminUser.username,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: `Admin '${adminUser.username}' published notice '${notice.title}' (${notice.visibility}).`,
  });

  res.status(201).json({
    success: true,
    message: 'NKETIAH School notice published.',
    data: { notice },
  });
}

export async function deleteSchoolNoticeHandler(req: Request, res: Response): Promise<void> {
  const adminUser = req.authUser!;
  const noticeId = String(req.params.id);

  const existing = await firestoreRepo.getDoc('schoolNotices', noticeId);
  if (!existing) {
    res.status(404).json({
      success: false,
      error: 'Notice not found.',
    });
    return;
  }

  await firestoreRepo.deleteDoc('schoolNotices', noticeId);

  await recordAuditLog({
    eventType: 'SCHOOL_NOTICE_DELETED',
    severity: 'WARNING',
    actorUserId: adminUser.id,
    actorUsername: adminUser.username,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: `Admin '${adminUser.username}' deleted notice '${existing.title}'.`,
  });

  res.status(200).json({
    success: true,
    message: 'Notice deleted.',
  });
}

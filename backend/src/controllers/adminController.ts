import { Request, Response } from 'express';
import { firestoreRepo } from '../config/firebase';
import { listAuditLogs, recordAuditLog } from '../services/auditService';
import {
  createDatabaseBackup,
  listBackupLogs,
  restoreDatabaseFromBackup,
} from '../services/backupService';
import { revokeAllUserSessions } from '../services/tokenService';
import { UserDocument } from '../types/models';
import {
  toSafeUserDTO,
  updateRoleRequestSchema,
  updateStatusRequestSchema,
} from '../utils/validators';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - ADMIN CONTROLLER (RBAC: ADMIN ONLY)
 * ============================================================================
 */

export async function listUsersAdminHandler(_req: Request, res: Response): Promise<void> {
  const users = await firestoreRepo.listDocs('users');
  const sorted = users
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map(toSafeUserDTO);

  res.status(200).json({
    success: true,
    data: {
      users: sorted,
      total: sorted.length,
    },
  });
}

export async function getUserByIdAdminHandler(req: Request, res: Response): Promise<void> {
  const userId = String(req.params.id);
  const user = await firestoreRepo.getDoc('users', userId);
  if (!user) {
    res.status(404).json({
      success: false,
      error: 'User not found.',
    });
    return;
  }

  res.status(200).json({
    success: true,
    data: {
      user: toSafeUserDTO(user),
    },
  });
}

export async function updateUserRoleAdminHandler(req: Request, res: Response): Promise<void> {
  const parsed = updateRoleRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      success: false,
      error: parsed.error.issues[0]?.message || 'Invalid role value.',
    });
    return;
  }

  const adminUser = req.authUser!;
  const targetUserId = String(req.params.id);
  const newRole = parsed.data.role;

  if (adminUser.id === targetUserId && newRole !== 'ADMIN') {
    res.status(400).json({
      success: false,
      error: 'Security policy prevents an Administrator from demoting their own account.',
    });
    return;
  }

  const targetUser = await firestoreRepo.getDoc('users', targetUserId);
  if (!targetUser) {
    res.status(404).json({
      success: false,
      error: 'Target user not found.',
    });
    return;
  }

  const previousRole = targetUser.role;
  const updated = (await firestoreRepo.updateDoc('users', targetUserId, {
    role: newRole,
    updatedAt: new Date().toISOString(),
  })) as UserDocument;

  await recordAuditLog({
    eventType: 'ADMIN_ROLE_CHANGED',
    severity: 'WARNING',
    actorUserId: adminUser.id,
    actorUsername: adminUser.username,
    targetUserId: updated.id,
    targetUsername: updated.username,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: `Admin '${adminUser.username}' changed role of '${updated.username}' from ${previousRole} to ${newRole}.`,
    metadata: { previousRole, newRole },
  });

  res.status(200).json({
    success: true,
    message: `User '${updated.username}' role updated to ${newRole}.`,
    data: {
      user: toSafeUserDTO(updated),
    },
  });
}

export async function updateUserStatusAdminHandler(req: Request, res: Response): Promise<void> {
  const parsed = updateStatusRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      success: false,
      error: parsed.error.issues[0]?.message || 'Invalid status value.',
    });
    return;
  }

  const adminUser = req.authUser!;
  const targetUserId = String(req.params.id);
  const newStatus = parsed.data.status;

  if (adminUser.id === targetUserId && newStatus === 'DISABLED') {
    res.status(400).json({
      success: false,
      error: 'Security policy prevents an Administrator from disabling their own account.',
    });
    return;
  }

  const targetUser = await firestoreRepo.getDoc('users', targetUserId);
  if (!targetUser) {
    res.status(404).json({
      success: false,
      error: 'Target user not found.',
    });
    return;
  }

  const updated = (await firestoreRepo.updateDoc('users', targetUserId, {
    status: newStatus,
    failedLoginAttempts: 0,
    lockoutUntil: null,
    updatedAt: new Date().toISOString(),
  })) as UserDocument;

  // If account is disabled, revoke all active refresh token sessions immediately
  if (newStatus === 'DISABLED') {
    await revokeAllUserSessions(targetUserId);
  }

  await recordAuditLog({
    eventType: 'ADMIN_STATUS_CHANGED',
    severity: newStatus === 'DISABLED' ? 'WARNING' : 'INFO',
    actorUserId: adminUser.id,
    actorUsername: adminUser.username,
    targetUserId: updated.id,
    targetUsername: updated.username,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: `Admin '${adminUser.username}' set account status of '${updated.username}' to ${newStatus}.`,
    metadata: { status: newStatus },
  });

  res.status(200).json({
    success: true,
    message: `User '${updated.username}' status updated to ${newStatus}.`,
    data: {
      user: toSafeUserDTO(updated),
    },
  });
}

export async function deleteUserAdminHandler(req: Request, res: Response): Promise<void> {
  const adminUser = req.authUser!;
  const targetUserId = String(req.params.id);

  if (adminUser.id === targetUserId) {
    res.status(400).json({
      success: false,
      error: 'Security policy prevents an Administrator from deleting their own account.',
    });
    return;
  }

  const targetUser = await firestoreRepo.getDoc('users', targetUserId);
  if (!targetUser) {
    res.status(404).json({
      success: false,
      error: 'Target user not found.',
    });
    return;
  }

  await revokeAllUserSessions(targetUserId);
  await firestoreRepo.deleteDoc('recoveryCodes', targetUserId);
  await firestoreRepo.deleteDoc('users', targetUserId);

  await recordAuditLog({
    eventType: 'ADMIN_USER_DELETED',
    severity: 'CRITICAL',
    actorUserId: adminUser.id,
    actorUsername: adminUser.username,
    targetUserId: targetUser.id,
    targetUsername: targetUser.username,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: `Admin '${adminUser.username}' permanently deleted user '${targetUser.username}'.`,
  });

  res.status(200).json({
    success: true,
    message: `User '${targetUser.username}' has been permanently deleted.`,
  });
}

export async function listAuditLogsAdminHandler(_req: Request, res: Response): Promise<void> {
  const logs = await listAuditLogs(150);
  res.status(200).json({
    success: true,
    data: {
      auditLogs: logs,
      total: logs.length,
    },
  });
}

export async function listBackupsAdminHandler(_req: Request, res: Response): Promise<void> {
  const backups = await listBackupLogs();
  res.status(200).json({
    success: true,
    data: {
      backups,
      total: backups.length,
      firestoreConnection: firestoreRepo.getConnectionInfo(),
    },
  });
}

export async function createBackupAdminHandler(req: Request, res: Response): Promise<void> {
  const adminUser = req.authUser!;
  try {
    const backupLog = await createDatabaseBackup({
      triggerType: 'ADMIN_API',
      triggeredByUsername: adminUser.username,
    });

    res.status(201).json({
      success: true,
      message: `Encrypted Firestore backup (${backupLog.filename}) created and verified.`,
      data: {
        backup: backupLog,
      },
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: (err as Error).message || 'Backup creation failed.',
    });
  }
}

export async function restoreBackupAdminHandler(req: Request, res: Response): Promise<void> {
  const adminUser = req.authUser!;
  const backupId = String(req.params.backupId);

  try {
    const result = await restoreDatabaseFromBackup(backupId, adminUser.username);
    res.status(200).json({
      success: true,
      message: `Database successfully restored from backup ${result.backupLog.filename}. SHA-256 and AES-256-GCM integrity verified.`,
      data: result,
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      error: (err as Error).message || 'Database restoration failed.',
    });
  }
}

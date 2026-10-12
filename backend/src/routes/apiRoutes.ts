import { Router } from 'express';
import {
  createBackupAdminHandler,
  deleteUserAdminHandler,
  getUserByIdAdminHandler,
  listAuditLogsAdminHandler,
  listBackupsAdminHandler,
  listUsersAdminHandler,
  restoreBackupAdminHandler,
  updateUserRoleAdminHandler,
  updateUserStatusAdminHandler,
} from '../controllers/adminController';
import {
  changePasswordHandler,
  disable2FAHandler,
  enable2FAHandler,
  getLive2FACodeHandler,
  getMeHandler,
  loginHandler,
  logoutHandler,
  refreshHandler,
  registerHandler,
  setup2FAHandler,
  verify2FAHandler,
} from '../controllers/authController';
import {
  createSchoolNoticeHandler,
  deleteSchoolNoticeHandler,
  getPublicSchoolOverviewHandler,
} from '../controllers/schoolController';
import { requireAuth, requireRole } from '../middleware/authMiddleware';
import { strictAuthLimiter } from '../middleware/rateLimiter';

export const apiRouter = Router();

// ============================================================================
// 1. PUBLIC & GUEST ROUTES (Accessible to GUEST, USER, ADMIN)
// ============================================================================
apiRouter.get('/school/overview', getPublicSchoolOverviewHandler);

// ============================================================================
// 2. AUTHENTICATION & 2FA ROUTES
// ============================================================================
apiRouter.post('/auth/register', strictAuthLimiter, registerHandler);
apiRouter.post('/auth/login', strictAuthLimiter, loginHandler);
apiRouter.post('/auth/verify-2fa', strictAuthLimiter, verify2FAHandler);
apiRouter.post('/auth/refresh', refreshHandler);
apiRouter.post('/auth/logout', logoutHandler);
apiRouter.post('/auth/2fa/live-code', getLive2FACodeHandler);

// Protected 2FA & Account Security Routes (Requires valid ACCESS JWT)
apiRouter.post('/auth/2fa/setup', requireAuth, setup2FAHandler);
apiRouter.post('/auth/2fa/enable', requireAuth, enable2FAHandler);
apiRouter.post('/auth/2fa/disable', requireAuth, disable2FAHandler);
apiRouter.post('/auth/change-password', requireAuth, changePasswordHandler);

// ============================================================================
// 3. USER PROFILE ROUTES (Requires USER or ADMIN role)
// ============================================================================
apiRouter.get('/users/me', requireAuth, requireRole('USER', 'ADMIN'), getMeHandler);

// ============================================================================
// 4. ADMIN MANAGEMENT, AUDIT LOGS & BACKUP/RESTORE ROUTES (Requires ADMIN role)
// ============================================================================
apiRouter.get('/admin/users', requireAuth, requireRole('ADMIN'), listUsersAdminHandler);
apiRouter.get('/admin/users/:id', requireAuth, requireRole('ADMIN'), getUserByIdAdminHandler);
apiRouter.patch(
  '/admin/users/:id/role',
  requireAuth,
  requireRole('ADMIN'),
  updateUserRoleAdminHandler
);
apiRouter.patch(
  '/admin/users/:id/status',
  requireAuth,
  requireRole('ADMIN'),
  updateUserStatusAdminHandler
);
apiRouter.delete(
  '/admin/users/:id',
  requireAuth,
  requireRole('ADMIN'),
  deleteUserAdminHandler
);

// School Noticeboard Admin Management
apiRouter.post(
  '/school/notices',
  requireAuth,
  requireRole('ADMIN'),
  createSchoolNoticeHandler
);
apiRouter.delete(
  '/school/notices/:id',
  requireAuth,
  requireRole('ADMIN'),
  deleteSchoolNoticeHandler
);

// Security Audit Logs & Automated Database Backups
apiRouter.get(
  '/admin/audit-logs',
  requireAuth,
  requireRole('ADMIN'),
  listAuditLogsAdminHandler
);
apiRouter.get('/admin/backups', requireAuth, requireRole('ADMIN'), listBackupsAdminHandler);
apiRouter.post(
  '/admin/backups',
  requireAuth,
  requireRole('ADMIN'),
  createBackupAdminHandler
);
apiRouter.post(
  '/admin/backups/:backupId/restore',
  requireAuth,
  requireRole('ADMIN'),
  restoreBackupAdminHandler
);

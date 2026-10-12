import { NextFunction, Request, Response } from 'express';
import { firestoreRepo } from '../config/firebase';
import { recordAuditLog } from '../services/auditService';
import { verifyAccessToken } from '../services/tokenService';
import { UserDocument, UserRole } from '../types/models';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - AUTHENTICATION & RBAC MIDDLEWARE
 * ============================================================================
 *
 * TEACHING NOTE:
 * 1. Authentication (`requireAuth`):
 *    Answers "Who are you?"
 *    Validates the JWT Access Token and verifies that the user account in
 *    Firestore is still `ACTIVE`.
 *
 * 2. Role-Based Authorization (`requireRole`):
 *    Answers "What are you allowed to do?"
 *    Enforced strictly on the Node.js Backend so a malicious user cannot
 *    bypass React or Expo frontend screens by calling the API with Postman/cURL.
 */

declare global {
  namespace Express {
    interface Request {
      authUser?: UserDocument;
    }
  }
}

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        success: false,
        error: 'Authentication required. Please provide a valid Bearer access token.',
      });
      return;
    }

    const token = authHeader.slice(7).trim();
    const payload = verifyAccessToken(token);

    // Fetch live user record from Firestore to ensure account hasn't been disabled or deleted
    const user = await firestoreRepo.getDoc('users', payload.sub);
    if (!user) {
      res.status(401).json({
        success: false,
        error: 'User account no longer exists.',
      });
      return;
    }

    if (user.status !== 'ACTIVE') {
      res.status(403).json({
        success: false,
        error: 'Your NKETIAH account has been disabled by an administrator.',
      });
      return;
    }

    req.authUser = user;
    next();
  } catch {
    res.status(401).json({
      success: false,
      error: 'Invalid or expired access token. Please log in or refresh your session.',
    });
  }
}

/**
 * Enforces Role-Based Access Control (GUEST / USER / ADMIN).
 */
export function requireRole(...allowedRoles: UserRole[]) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const user = req.authUser;
    if (!user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required.',
      });
      return;
    }

    if (!allowedRoles.includes(user.role)) {
      await recordAuditLog({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'WARNING',
        actorUserId: user.id,
        actorUsername: user.username,
        ipAddress: req.ip || '127.0.0.1',
        userAgent: req.headers['user-agent'] || 'Unknown',
        details: `User '${user.username}' with role '${user.role}' attempted to access restricted endpoint ${req.method} ${req.originalUrl} (Requires: ${allowedRoles.join(', ')}).`,
      });

      res.status(403).json({
        success: false,
        error: `Access denied. Insufficient privileges. Required role: ${allowedRoles.join(' or ')}.`,
      });
      return;
    }

    next();
  };
}

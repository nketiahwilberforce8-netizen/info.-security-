import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';
import { firestoreRepo } from '../config/firebase';
import { SessionDocument, UserDocument, UserRole } from '../types/models';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - TOKEN & SESSION ARCHITECTURE SERVICE
 * ============================================================================
 *
 * TEACHING NOTE ON OUR UNIFIED WEB + MOBILE TOKEN ARCHITECTURE:
 * 1. Pre-2FA Token (JWT, 5 minutes):
 *    Issued when a user with 2FA enabled enters a valid Username + Password.
 *    It carries `purpose: 'PRE_2FA_VERIFICATION'` and is REJECTED by all normal
 *    API endpoints. It can ONLY be used at `POST /api/auth/verify-2fa`.
 *
 * 2. Access Token (JWT, 15 minutes):
 *    Issued only after full authentication (Password + 2FA if enabled).
 *    Contains `{ sub: userId, username, role }`.
 *    - React Web keeps this in memory (React state), preventing localStorage XSS theft.
 *    - Expo Mobile keeps this in hardware-backed `expo-secure-store`.
 *
 * 3. Refresh Token (Opaque 256-bit random token, 7 days):
 *    - Stored as a SHA-256 hash inside the Firestore `sessions` collection.
 *    - Sent to React Web as an `HttpOnly; SameSite=Strict` cookie AND in the
 *      JSON payload for Expo Mobile (`expo-secure-store`).
 *    - Supports Token Rotation (each refresh invalidates the old session token and
 *      issues a brand new one) and instant Session Revocation on logout or admin ban.
 */

export interface AccessTokenPayload {
  sub: string;
  username: string;
  role: UserRole;
  type: 'ACCESS';
}

export interface Pre2FATokenPayload {
  sub: string;
  username: string;
  type: 'PRE_2FA';
}

export function hashRefreshToken(rawRefreshToken: string): string {
  return crypto.createHash('sha256').update(rawRefreshToken, 'utf8').digest('hex');
}

export function signAccessToken(user: Pick<UserDocument, 'id' | 'username' | 'role'>): string {
  const payload: AccessTokenPayload = {
    sub: user.id,
    username: user.username,
    role: user.role,
    type: 'ACCESS',
  };

  return jwt.sign(payload, env.JWT_ACCESS_SECRET, {
    expiresIn: env.ACCESS_TOKEN_EXPIRES_IN as jwt.SignOptions['expiresIn'],
    issuer: 'nketiah-security-api',
  });
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  const decoded = jwt.verify(token, env.JWT_ACCESS_SECRET, {
    issuer: 'nketiah-security-api',
  }) as AccessTokenPayload;

  if (decoded.type !== 'ACCESS') {
    throw new Error('Invalid token type: expected ACCESS token.');
  }

  return decoded;
}

export function signPre2FAToken(user: Pick<UserDocument, 'id' | 'username'>): string {
  const payload: Pre2FATokenPayload = {
    sub: user.id,
    username: user.username,
    type: 'PRE_2FA',
  };

  return jwt.sign(payload, env.JWT_PRE_2FA_SECRET, {
    expiresIn: env.PRE_2FA_TOKEN_EXPIRES_IN as jwt.SignOptions['expiresIn'],
    issuer: 'nketiah-security-api',
  });
}

export function verifyPre2FAToken(token: string): Pre2FATokenPayload {
  const decoded = jwt.verify(token, env.JWT_PRE_2FA_SECRET, {
    issuer: 'nketiah-security-api',
  }) as Pre2FATokenPayload;

  if (decoded.type !== 'PRE_2FA') {
    throw new Error('Invalid token type: expected PRE_2FA token.');
  }

  return decoded;
}

/**
 * Issues a new 256-bit opaque Refresh Token and records its SHA-256 hash in Firestore `sessions`.
 */
export async function createRefreshTokenSession(
  user: Pick<UserDocument, 'id' | 'username'>,
  ipAddress: string,
  userAgent: string
): Promise<{ rawRefreshToken: string; session: SessionDocument }> {
  const sessionId = `ses_${crypto.randomUUID()}`;
  const rawSecret = crypto.randomBytes(32).toString('hex');
  const rawRefreshToken = `${sessionId}.${rawSecret}`;
  const refreshTokenHash = hashRefreshToken(rawRefreshToken);

  const now = new Date();
  const expiresAt = new Date(
    now.getTime() + env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
  ).toISOString();

  const session: SessionDocument = {
    id: sessionId,
    userId: user.id,
    username: user.username,
    refreshTokenHash,
    userAgent: userAgent || 'Unknown Client',
    ipAddress: ipAddress || '127.0.0.1',
    revoked: false,
    expiresAt,
    createdAt: now.toISOString(),
    rotatedAt: null,
  };

  await firestoreRepo.setDoc('sessions', sessionId, session);

  return { rawRefreshToken, session };
}

/**
 * Rotates a Refresh Token:
 * 1. Verifies the session exists, is not revoked, and hasn't expired.
 * 2. Verifies the SHA-256 hash matches.
 * 3. Revokes the old session token and issues a brand new refresh token + access token.
 */
export async function rotateRefreshTokenSession(
  rawRefreshToken: string,
  ipAddress: string,
  userAgent: string
): Promise<{
  user: UserDocument;
  accessToken: string;
  newRefreshToken: string;
}> {
  const parts = rawRefreshToken.split('.');
  if (parts.length !== 2) {
    throw new Error('Malformed refresh token.');
  }

  const [sessionId] = parts;
  const session = await firestoreRepo.getDoc('sessions', sessionId);

  if (!session) {
    throw new Error('Session not found.');
  }

  if (session.revoked) {
    // Security defense: If a revoked refresh token is reused, revoke all sessions for that user!
    await revokeAllUserSessions(session.userId);
    throw new Error('Refresh token has been revoked.');
  }

  if (new Date(session.expiresAt).getTime() <= Date.now()) {
    await firestoreRepo.updateDoc('sessions', sessionId, { revoked: true });
    throw new Error('Refresh token has expired.');
  }

  const candidateHash = hashRefreshToken(rawRefreshToken);
  if (candidateHash !== session.refreshTokenHash) {
    throw new Error('Invalid refresh token signature.');
  }

  const user = await firestoreRepo.getDoc('users', session.userId);
  if (!user || user.status !== 'ACTIVE') {
    await firestoreRepo.updateDoc('sessions', sessionId, { revoked: true });
    throw new Error('User account is disabled or no longer exists.');
  }

  // Revoke old session
  await firestoreRepo.updateDoc('sessions', sessionId, {
    revoked: true,
    rotatedAt: new Date().toISOString(),
  });

  // Issue new rotated session + access token
  const { rawRefreshToken: newRefreshToken } = await createRefreshTokenSession(
    user,
    ipAddress,
    userAgent
  );
  const accessToken = signAccessToken(user);

  return { user, accessToken, newRefreshToken };
}

export async function revokeRefreshToken(rawRefreshToken?: string): Promise<void> {
  if (!rawRefreshToken) return;
  const [sessionId] = rawRefreshToken.split('.');
  if (!sessionId) return;
  const existing = await firestoreRepo.getDoc('sessions', sessionId);
  if (existing) {
    await firestoreRepo.updateDoc('sessions', sessionId, {
      revoked: true,
      rotatedAt: new Date().toISOString(),
    });
  }
}

export async function revokeAllUserSessions(userId: string): Promise<number> {
  const allSessions = await firestoreRepo.listDocs('sessions');
  const userActiveSessions = allSessions.filter(
    (s) => s.userId === userId && !s.revoked
  );

  for (const s of userActiveSessions) {
    await firestoreRepo.updateDoc('sessions', s.id, {
      revoked: true,
      rotatedAt: new Date().toISOString(),
    });
  }

  return userActiveSessions.length;
}

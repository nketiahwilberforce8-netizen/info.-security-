import crypto from 'crypto';
import { Request, Response } from 'express';
import { env } from '../config/env';
import { firestoreRepo } from '../config/firebase';
import { recordAuditLog } from '../services/auditService';
import { decryptAes256Gcm, encryptAes256Gcm } from '../services/encryptionService';
import {
  hashPassword,
  performDummyPasswordVerify,
  verifyPassword,
} from '../services/passwordService';
import {
  createRefreshTokenSession,
  revokeAllUserSessions,
  revokeRefreshToken,
  rotateRefreshTokenSession,
  signAccessToken,
  signPre2FAToken,
  verifyPre2FAToken,
} from '../services/tokenService';
import {
  generateRecoveryCodes,
  generateTotpCode,
  generateTotpQrCode,
  generateTotpSecret,
  hashRecoveryCode,
  verifyTotpCode,
} from '../services/totpService';
import { UserDocument } from '../types/models';
import {
  changePasswordRequestSchema,
  disable2FARequestSchema,
  enable2FARequestSchema,
  loginRequestSchema,
  registerRequestSchema,
  toSafeUserDTO,
  verify2FARequestSchema,
} from '../utils/validators';

const MAX_FAILED_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
const REFRESH_COOKIE_NAME = 'nketiah_refresh_token';

function setRefreshCookie(res: Response, rawRefreshToken: string): void {
  res.cookie(REFRESH_COOKIE_NAME, rawRefreshToken, {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
    path: '/api/auth',
  });
}

function clearRefreshCookie(res: Response): void {
  res.clearCookie(REFRESH_COOKIE_NAME, {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/auth',
  });
}

/**
 * POST /api/auth/register
 * Registers a new NKETIAH user using ONLY Username + Password (+ Confirm Password).
 */
export async function registerHandler(req: Request, res: Response): Promise<void> {
  const parsed = registerRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      success: false,
      error: parsed.error.issues[0]?.message || 'Invalid registration data.',
      issues: parsed.error.issues,
    });
    return;
  }

  const { username, password, fullName, department } = parsed.data;
  const usernameNormalized = username.trim().toLowerCase();

  // Check uniqueness of username
  const existingUser = await firestoreRepo.findUserByUsername(usernameNormalized);
  if (existingUser) {
    res.status(409).json({
      success: false,
      error: 'That username is already registered in the NKETIAH system.',
    });
    return;
  }

  // Hash password with Argon2id + Unique Salt + Server-Side Pepper
  const passwordHash = await hashPassword(password);

  const now = new Date().toISOString();
  const userId = `usr_${crypto.randomUUID()}`;
  const randomDigits = Math.floor(1000 + Math.random() * 9000);
  const studentOrStaffId = `NK-STU-2026-${randomDigits}`;

  const newUser: UserDocument = {
    id: userId,
    username: username.trim(),
    usernameNormalized,
    fullName: fullName?.trim() || username.trim(),
    department: department?.trim() || 'Information Technology',
    studentOrStaffId,
    role: 'USER',
    status: 'ACTIVE',
    passwordHash,
    twoFactorEnabled: false,
    totpSecretEncrypted: null,
    pendingTotpSecretEncrypted: null,
    failedLoginAttempts: 0,
    lockoutUntil: null,
    lastLoginAt: now,
    createdAt: now,
    updatedAt: now,
  };

  await firestoreRepo.setDoc('users', userId, newUser);

  // Issue initial session & tokens
  const ip = req.ip || '127.0.0.1';
  const ua = req.headers['user-agent'] || 'Unknown';
  const accessToken = signAccessToken(newUser);
  const { rawRefreshToken } = await createRefreshTokenSession(newUser, ip, ua);
  setRefreshCookie(res, rawRefreshToken);

  await recordAuditLog({
    eventType: 'REGISTER_SUCCESS',
    severity: 'INFO',
    actorUserId: newUser.id,
    actorUsername: newUser.username,
    ipAddress: ip,
    userAgent: ua,
    details: `New NKETIAH user '${newUser.username}' (${newUser.studentOrStaffId}) registered successfully.`,
  });

  res.status(201).json({
    success: true,
    message: 'Registration successful. Welcome to NKETIAH School Management System.',
    data: {
      user: toSafeUserDTO(newUser),
      accessToken,
      refreshToken: rawRefreshToken, // Used by Expo Mobile SecureStore
    },
  });
}

/**
 * POST /api/auth/login
 * Authenticates via Username + Password.
 * If 2FA is enabled, returns `requiresTwoFactor: true` + `preAuthToken` (no access token yet!).
 */
export async function loginHandler(req: Request, res: Response): Promise<void> {
  const parsed = loginRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      success: false,
      error: parsed.error.issues[0]?.message || 'Invalid login request.',
    });
    return;
  }

  const { username, password } = parsed.data;
  const ip = req.ip || '127.0.0.1';
  const ua = req.headers['user-agent'] || 'Unknown';

  const user = await firestoreRepo.findUserByUsername(username);
  if (!user) {
    // Perform dummy Argon2id verification to prevent username timing enumeration
    await performDummyPasswordVerify(password);
    await recordAuditLog({
      eventType: 'LOGIN_FAILED',
      severity: 'WARNING',
      actorUsername: username,
      ipAddress: ip,
      userAgent: ua,
      details: `Failed login attempt for non-existent username '${username}'.`,
    });

    res.status(401).json({
      success: false,
      error: 'Invalid username or password.',
    });
    return;
  }

  // Check if account is disabled by an Administrator
  if (user.status !== 'ACTIVE') {
    await recordAuditLog({
      eventType: 'LOGIN_FAILED',
      severity: 'WARNING',
      actorUserId: user.id,
      actorUsername: user.username,
      ipAddress: ip,
      userAgent: ua,
      details: `Blocked login attempt on disabled account '${user.username}'.`,
    });

    res.status(403).json({
      success: false,
      error: 'Your NKETIAH account has been disabled by an administrator.',
    });
    return;
  }

  // Check temporary brute-force lockout
  if (user.lockoutUntil && new Date(user.lockoutUntil).getTime() > Date.now()) {
    const remainingMinutes = Math.ceil(
      (new Date(user.lockoutUntil).getTime() - Date.now()) / 60000
    );
    res.status(423).json({
      success: false,
      error: `Account is temporarily locked due to multiple failed login attempts. Try again in ${remainingMinutes} minute(s).`,
    });
    return;
  }

  // Verify password using Argon2id + Server-Side Pepper
  const isPasswordValid = await verifyPassword(password, user.passwordHash);
  if (!isPasswordValid) {
    const newFailedCount = (user.failedLoginAttempts || 0) + 1;
    const shouldLock = newFailedCount >= MAX_FAILED_LOGIN_ATTEMPTS;
    const lockoutUntil = shouldLock
      ? new Date(Date.now() + LOCKOUT_DURATION_MS).toISOString()
      : null;

    await firestoreRepo.updateDoc('users', user.id, {
      failedLoginAttempts: newFailedCount,
      lockoutUntil,
      updatedAt: new Date().toISOString(),
    });

    await recordAuditLog({
      eventType: shouldLock ? 'ACCOUNT_LOCKED' : 'LOGIN_FAILED',
      severity: shouldLock ? 'CRITICAL' : 'WARNING',
      actorUserId: user.id,
      actorUsername: user.username,
      ipAddress: ip,
      userAgent: ua,
      details: shouldLock
        ? `Account '${user.username}' locked for 15 minutes after ${newFailedCount} consecutive failed password attempts.`
        : `Invalid password attempt (${newFailedCount}/${MAX_FAILED_LOGIN_ATTEMPTS}) for '${user.username}'.`,
    });

    res.status(401).json({
      success: false,
      error: shouldLock
        ? 'Account locked for 15 minutes due to 5 failed login attempts.'
        : 'Invalid username or password.',
    });
    return;
  }

  // Password is valid -> reset failed login counter
  const now = new Date().toISOString();
  await firestoreRepo.updateDoc('users', user.id, {
    failedLoginAttempts: 0,
    lockoutUntil: null,
    updatedAt: now,
  });

  // Check if Two-Factor Authentication (2FA) is enabled for this user
  if (user.twoFactorEnabled && user.totpSecretEncrypted) {
    const preAuthToken = signPre2FAToken(user);
    res.status(200).json({
      success: true,
      requiresTwoFactor: true,
      message: 'Password verified. Please enter your 6-digit 2FA authenticator code or recovery code.',
      data: {
        preAuthToken,
        username: user.username,
      },
    });
    return;
  }

  // No 2FA enabled -> issue full session tokens
  const updatedUser = (await firestoreRepo.updateDoc('users', user.id, {
    lastLoginAt: now,
  })) as UserDocument;

  const accessToken = signAccessToken(updatedUser);
  const { rawRefreshToken } = await createRefreshTokenSession(updatedUser, ip, ua);
  setRefreshCookie(res, rawRefreshToken);

  await recordAuditLog({
    eventType: 'LOGIN_SUCCESS',
    severity: 'INFO',
    actorUserId: updatedUser.id,
    actorUsername: updatedUser.username,
    ipAddress: ip,
    userAgent: ua,
    details: `User '${updatedUser.username}' (${updatedUser.role}) logged in successfully.`,
  });

  res.status(200).json({
    success: true,
    requiresTwoFactor: false,
    message: 'Login successful.',
    data: {
      user: toSafeUserDTO(updatedUser),
      accessToken,
      refreshToken: rawRefreshToken,
    },
  });
}

/**
 * Helper to verify either a 6-digit TOTP code OR a one-time Recovery Code for a user.
 */
async function verifyTotpOrRecoveryCodeForUser(
  user: UserDocument,
  rawCode: string
): Promise<{ valid: boolean; usedRecoveryCode: boolean; remainingRecoveryCodes?: number }> {
  if (!user.totpSecretEncrypted) {
    return { valid: false, usedRecoveryCode: false };
  }

  const cleaned = rawCode.trim();

  // Case 1: 6-digit TOTP code from Authenticator App
  if (/^\d{6}$/.test(cleaned)) {
    const decryptedBase32Secret = decryptAes256Gcm(user.totpSecretEncrypted);
    const isTotpValid = verifyTotpCode(cleaned, decryptedBase32Secret);
    return { valid: isTotpValid, usedRecoveryCode: false };
  }

  // Case 2: One-time Recovery Code (e.g., "NKET-XXXX-XXXX")
  const recoveryDoc = await firestoreRepo.getDoc('recoveryCodes', user.id);
  if (!recoveryDoc) {
    return { valid: false, usedRecoveryCode: false };
  }

  const candidateHash = hashRecoveryCode(cleaned);
  const matchIndex = recoveryDoc.codes.findIndex(
    (entry) => !entry.used && entry.codeHash === candidateHash
  );

  if (matchIndex === -1) {
    return { valid: false, usedRecoveryCode: false };
  }

  // Mark recovery code as used so it can never be reused
  recoveryDoc.codes[matchIndex].used = true;
  recoveryDoc.codes[matchIndex].usedAt = new Date().toISOString();
  await firestoreRepo.setDoc('recoveryCodes', user.id, recoveryDoc);

  const remaining = recoveryDoc.codes.filter((c) => !c.used).length;
  return { valid: true, usedRecoveryCode: true, remainingRecoveryCodes: remaining };
}

/**
 * POST /api/auth/verify-2fa
 * Completes the 2nd step of authentication using either a 6-digit TOTP code or a Recovery Code.
 */
export async function verify2FAHandler(req: Request, res: Response): Promise<void> {
  const parsed = verify2FARequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      success: false,
      error: parsed.error.issues[0]?.message || 'Invalid 2FA verification request.',
    });
    return;
  }

  const { preAuthToken, code } = parsed.data;
  const ip = req.ip || '127.0.0.1';
  const ua = req.headers['user-agent'] || 'Unknown';

  let tokenPayload;
  try {
    tokenPayload = verifyPre2FAToken(preAuthToken);
  } catch {
    res.status(401).json({
      success: false,
      error: '2FA verification session expired or is invalid. Please log in again.',
    });
    return;
  }

  const user = await firestoreRepo.getDoc('users', tokenPayload.sub);
  if (!user || user.status !== 'ACTIVE' || !user.twoFactorEnabled) {
    res.status(401).json({
      success: false,
      error: 'User account is unavailable or 2FA is not active.',
    });
    return;
  }

  const verification = await verifyTotpOrRecoveryCodeForUser(user, code);
  if (!verification.valid) {
    await recordAuditLog({
      eventType: '2FA_VERIFY_FAILED',
      severity: 'WARNING',
      actorUserId: user.id,
      actorUsername: user.username,
      ipAddress: ip,
      userAgent: ua,
      details: `Invalid 2FA code submitted for user '${user.username}'.`,
    });

    res.status(401).json({
      success: false,
      error: 'Invalid 2FA verification code or recovery code.',
    });
    return;
  }

  const now = new Date().toISOString();
  const updatedUser = (await firestoreRepo.updateDoc('users', user.id, {
    lastLoginAt: now,
    updatedAt: now,
  })) as UserDocument;

  const accessToken = signAccessToken(updatedUser);
  const { rawRefreshToken } = await createRefreshTokenSession(updatedUser, ip, ua);
  setRefreshCookie(res, rawRefreshToken);

  await recordAuditLog({
    eventType: verification.usedRecoveryCode ? '2FA_RECOVERY_CODE_USED' : '2FA_VERIFY_SUCCESS',
    severity: verification.usedRecoveryCode ? 'WARNING' : 'INFO',
    actorUserId: updatedUser.id,
    actorUsername: updatedUser.username,
    ipAddress: ip,
    userAgent: ua,
    details: verification.usedRecoveryCode
      ? `User '${updatedUser.username}' logged in using a one-time 2FA recovery code (${verification.remainingRecoveryCodes} remaining).`
      : `User '${updatedUser.username}' verified TOTP 2FA and logged in successfully.`,
  });

  res.status(200).json({
    success: true,
    message: verification.usedRecoveryCode
      ? `Login successful via recovery code. You have ${verification.remainingRecoveryCodes} recovery codes left.`
      : 'Two-factor authentication verified. Login successful.',
    data: {
      user: toSafeUserDTO(updatedUser),
      accessToken,
      refreshToken: rawRefreshToken,
      usedRecoveryCode: verification.usedRecoveryCode,
      remainingRecoveryCodes: verification.remainingRecoveryCodes,
    },
  });
}

/**
 * POST /api/auth/2fa/setup
 * Generates a new TOTP secret, encrypts it with AES-256-GCM in `pendingTotpSecretEncrypted`,
 * and returns the QR code image + manual Base32 setup key.
 */
export async function setup2FAHandler(req: Request, res: Response): Promise<void> {
  const user = req.authUser!;
  const ip = req.ip || '127.0.0.1';
  const ua = req.headers['user-agent'] || 'Unknown';

  if (user.twoFactorEnabled) {
    res.status(400).json({
      success: false,
      error: 'Two-Factor Authentication is already enabled on your account.',
    });
    return;
  }

  const base32Secret = generateTotpSecret();
  const encryptedPendingSecret = encryptAes256Gcm(base32Secret);
  const { otpauthUrl, qrCodeDataUrl } = await generateTotpQrCode(
    user.username,
    base32Secret
  );

  await firestoreRepo.updateDoc('users', user.id, {
    pendingTotpSecretEncrypted: encryptedPendingSecret,
    updatedAt: new Date().toISOString(),
  });

  await recordAuditLog({
    eventType: '2FA_SETUP_INITIATED',
    severity: 'INFO',
    actorUserId: user.id,
    actorUsername: user.username,
    ipAddress: ip,
    userAgent: ua,
    details: `User '${user.username}' initiated TOTP 2FA setup (secret encrypted with AES-256-GCM).`,
  });

  const currentTotpCode = generateTotpCode(base32Secret);
  const secondsRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);

  res.status(200).json({
    success: true,
    message:
      'Scan the QR code with Google/Microsoft Authenticator, or use the live server TOTP code below if your PC clock date differs from your phone.',
    data: {
      qrCodeDataUrl,
      manualEntryKey: base32Secret,
      otpauthUrl,
      currentTotpCode,
      secondsRemaining,
      serverTimeIso: new Date().toISOString(),
      encryptionInfo: {
        algorithm: 'AES-256-GCM',
        ivLengthBits: 96,
        authTagLengthBits: 128,
      },
    },
  });
}

/**
 * POST /api/auth/2fa/live-code
 * Returns the live 6-digit RFC 6238 TOTP code computed by the server's clock
 * (by decrypting the user's AES-256-GCM TOTP secret in RAM).
 * Useful when the student's Windows PC calendar date (e.g. Oct 2026) differs from
 * their smartphone's date, or during classroom demonstrations without a phone.
 */
export async function getLive2FACodeHandler(req: Request, res: Response): Promise<void> {
  try {
    let targetUser: UserDocument | null = req.authUser ?? null;

    if (!targetUser && req.body?.preAuthToken) {
      const payload = verifyPre2FAToken(String(req.body.preAuthToken));
      targetUser = await firestoreRepo.getDoc('users', payload.sub);
    } else if (!targetUser) {
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith('Bearer ')) {
        const { verifyAccessToken } = await import('../services/tokenService');
        const decoded = verifyAccessToken(authHeader.slice(7).trim());
        targetUser = await firestoreRepo.getDoc('users', decoded.sub);
      }
    }

    if (!targetUser) {
      res.status(401).json({
        success: false,
        error: 'Authentication or preAuthToken required.',
      });
      return;
    }

    const encryptedSecret =
      targetUser.pendingTotpSecretEncrypted || targetUser.totpSecretEncrypted;

    if (!encryptedSecret) {
      res.status(400).json({
        success: false,
        error: 'No TOTP secret configured for this account.',
      });
      return;
    }

    const decryptedBase32Secret = decryptAes256Gcm(encryptedSecret);
    const currentTotpCode = generateTotpCode(decryptedBase32Secret);
    const secondsRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);

    res.status(200).json({
      success: true,
      data: {
        currentTotpCode,
        secondsRemaining,
        serverTimeIso: new Date().toISOString(),
      },
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      error: (err as Error).message || 'Could not compute live TOTP code.',
    });
  }
}

/**
 * POST /api/auth/2fa/enable
 * Verifies the initial 6-digit code against the decrypted pending TOTP secret,
 * enables 2FA, and generates 8 one-time recovery codes.
 */
export async function enable2FAHandler(req: Request, res: Response): Promise<void> {
  const parsed = enable2FARequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      success: false,
      error: parsed.error.issues[0]?.message || 'Enter a valid 6-digit code.',
    });
    return;
  }

  const user = req.authUser!;
  const ip = req.ip || '127.0.0.1';
  const ua = req.headers['user-agent'] || 'Unknown';

  // Fetch fresh user document from Firestore to ensure pendingTotpSecretEncrypted is up to date
  const freshUser = (await firestoreRepo.getDoc('users', user.id)) || user;

  if (!freshUser.pendingTotpSecretEncrypted) {
    res.status(400).json({
      success: false,
      error: 'No pending 2FA setup found. Please click Generate TOTP Secret & QR Code first.',
    });
    return;
  }

  const decryptedSecret = decryptAes256Gcm(freshUser.pendingTotpSecretEncrypted);
  const isValid = verifyTotpCode(parsed.data.code, decryptedSecret);

  if (!isValid) {
    const expectedNow = generateTotpCode(decryptedSecret);
    res.status(400).json({
      success: false,
      error: `Invalid 6-digit code (${parsed.data.code}) for server clock (${new Date().toISOString().slice(0, 10)}). Current valid code on server clock is ${expectedNow}. (If your PC date differs from your phone date, click "Auto-Fill Server TOTP Code" below!)`,
      expectedCodeHint: expectedNow,
    });
    return;
  }

  const { plainCodes, hashedEntries } = generateRecoveryCodes(8);
  const now = new Date().toISOString();

  await firestoreRepo.setDoc('recoveryCodes', freshUser.id, {
    id: freshUser.id,
    userId: freshUser.id,
    codes: hashedEntries,
    generatedAt: now,
  });

  const updatedUser = (await firestoreRepo.updateDoc('users', freshUser.id, {
    twoFactorEnabled: true,
    totpSecretEncrypted: freshUser.pendingTotpSecretEncrypted,
    pendingTotpSecretEncrypted: null,
    updatedAt: now,
  })) as UserDocument;

  await recordAuditLog({
    eventType: '2FA_ENABLED',
    severity: 'INFO',
    actorUserId: freshUser.id,
    actorUsername: freshUser.username,
    ipAddress: ip,
    userAgent: ua,
    details: `User '${freshUser.username}' enabled TOTP 2FA and generated 8 hashed recovery codes.`,
  });

  res.status(200).json({
    success: true,
    message: 'Two-Factor Authentication is now ACTIVE! Save your 8 recovery codes below—they will only be shown once.',
    data: {
      user: toSafeUserDTO(updatedUser),
      recoveryCodes: plainCodes,
    },
  });
}

/**
 * POST /api/auth/2fa/disable
 * Disables 2FA after verifying both the user's current password AND a valid TOTP/recovery code.
 */
export async function disable2FAHandler(req: Request, res: Response): Promise<void> {
  const parsed = disable2FARequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      success: false,
      error: parsed.error.issues[0]?.message || 'Password and 2FA code are required.',
    });
    return;
  }

  const user = req.authUser!;
  const ip = req.ip || '127.0.0.1';
  const ua = req.headers['user-agent'] || 'Unknown';

  if (!user.twoFactorEnabled) {
    res.status(400).json({
      success: false,
      error: 'Two-Factor Authentication is not currently enabled.',
    });
    return;
  }

  const passwordOk = await verifyPassword(parsed.data.password, user.passwordHash);
  if (!passwordOk) {
    res.status(401).json({
      success: false,
      error: 'Incorrect password.',
    });
    return;
  }

  const codeCheck = await verifyTotpOrRecoveryCodeForUser(user, parsed.data.code);
  if (!codeCheck.valid) {
    res.status(401).json({
      success: false,
      error: 'Invalid 2FA authenticator code or recovery code.',
    });
    return;
  }

  const updatedUser = (await firestoreRepo.updateDoc('users', user.id, {
    twoFactorEnabled: false,
    totpSecretEncrypted: null,
    pendingTotpSecretEncrypted: null,
    updatedAt: new Date().toISOString(),
  })) as UserDocument;

  await firestoreRepo.deleteDoc('recoveryCodes', user.id);

  await recordAuditLog({
    eventType: '2FA_DISABLED',
    severity: 'WARNING',
    actorUserId: user.id,
    actorUsername: user.username,
    ipAddress: ip,
    userAgent: ua,
    details: `User '${user.username}' disabled Two-Factor Authentication.`,
  });

  res.status(200).json({
    success: true,
    message: 'Two-Factor Authentication has been disabled.',
    data: {
      user: toSafeUserDTO(updatedUser),
    },
  });
}

/**
 * POST /api/auth/refresh
 * Rotates a Refresh Token (from HttpOnly cookie or request body for mobile) and issues a new Access Token.
 */
export async function refreshHandler(req: Request, res: Response): Promise<void> {
  const cookieToken = req.cookies?.[REFRESH_COOKIE_NAME];
  const bodyToken = req.body?.refreshToken;
  const rawRefreshToken = bodyToken || cookieToken;

  if (!rawRefreshToken || typeof rawRefreshToken !== 'string') {
    res.status(401).json({
      success: false,
      error: 'No refresh token provided.',
    });
    return;
  }

  try {
    const ip = req.ip || '127.0.0.1';
    const ua = req.headers['user-agent'] || 'Unknown';
    const { user, accessToken, newRefreshToken } = await rotateRefreshTokenSession(
      rawRefreshToken,
      ip,
      ua
    );

    setRefreshCookie(res, newRefreshToken);

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully.',
      data: {
        user: toSafeUserDTO(user),
        accessToken,
        refreshToken: newRefreshToken,
      },
    });
  } catch (err) {
    clearRefreshCookie(res);
    res.status(401).json({
      success: false,
      error: (err as Error).message || 'Invalid or expired refresh token.',
    });
  }
}

/**
 * POST /api/auth/logout
 * Revokes the current refresh token session and clears the HttpOnly cookie.
 */
export async function logoutHandler(req: Request, res: Response): Promise<void> {
  const cookieToken = req.cookies?.[REFRESH_COOKIE_NAME];
  const bodyToken = req.body?.refreshToken;
  const rawRefreshToken = bodyToken || cookieToken;

  await revokeRefreshToken(rawRefreshToken);
  clearRefreshCookie(res);

  if (req.authUser) {
    await recordAuditLog({
      eventType: 'LOGOUT',
      severity: 'INFO',
      actorUserId: req.authUser.id,
      actorUsername: req.authUser.username,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.headers['user-agent'] || 'Unknown',
      details: `User '${req.authUser.username}' logged out and revoked session.`,
    });
  }

  res.status(200).json({
    success: true,
    message: 'Logged out successfully.',
  });
}

/**
 * POST /api/auth/change-password
 * Allows an authenticated user to change their password (re-hashes with a new salt + server pepper
 * and revokes old sessions).
 */
export async function changePasswordHandler(req: Request, res: Response): Promise<void> {
  const parsed = changePasswordRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      success: false,
      error: parsed.error.issues[0]?.message || 'Invalid password change input.',
    });
    return;
  }

  const user = req.authUser!;
  const { currentPassword, newPassword } = parsed.data;

  const isCurrentValid = await verifyPassword(currentPassword, user.passwordHash);
  if (!isCurrentValid) {
    res.status(401).json({
      success: false,
      error: 'Current password is incorrect.',
    });
    return;
  }

  const newPasswordHash = await hashPassword(newPassword);
  await firestoreRepo.updateDoc('users', user.id, {
    passwordHash: newPasswordHash,
    updatedAt: new Date().toISOString(),
  });

  await revokeAllUserSessions(user.id);

  await recordAuditLog({
    eventType: 'PASSWORD_CHANGED',
    severity: 'INFO',
    actorUserId: user.id,
    actorUsername: user.username,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    details: `User '${user.username}' changed their password (re-hashed with new Argon2id salt + server pepper).`,
  });

  res.status(200).json({
    success: true,
    message: 'Password updated successfully.',
  });
}

/**
 * GET /api/users/me
 * Returns the currently authenticated user's profile and 2FA recovery code count.
 */
export async function getMeHandler(req: Request, res: Response): Promise<void> {
  const user = req.authUser!;
  const recoveryDoc = await firestoreRepo.getDoc('recoveryCodes', user.id);
  const remainingRecoveryCodes = recoveryDoc
    ? recoveryDoc.codes.filter((c) => !c.used).length
    : 0;

  res.status(200).json({
    success: true,
    data: {
      user: toSafeUserDTO(user),
      securityProfile: {
        passwordHashAlgorithm: 'Argon2id (64 MiB, 3 iterations, 128-bit unique salt + HMAC-SHA256 Server Pepper)',
        totpEncryptionAlgorithm: user.twoFactorEnabled ? 'AES-256-GCM (96-bit IV + 128-bit Auth Tag)' : 'Not Active',
        twoFactorEnabled: user.twoFactorEnabled,
        remainingRecoveryCodes,
      },
    },
  });
}

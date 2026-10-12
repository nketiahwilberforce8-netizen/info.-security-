import { z } from 'zod';
import { SafeUserDTO, UserDocument } from '../types/models';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - ZOD INPUT VALIDATION & SANITIZATION
 * ============================================================================
 *
 * Notice that registration and login strictly use `username` and `password`.
 * Email addresses and phone numbers are NEVER required!
 */

export const usernameSchema = z
  .string()
  .trim()
  .min(3, 'Username must be at least 3 characters long.')
  .max(30, 'Username cannot exceed 30 characters.')
  .regex(
    /^[a-zA-Z0-9_.-]+$/,
    'Username may only contain letters, numbers, underscores (_), dots (.), and hyphens (-).'
  );

export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters long.')
  .max(128, 'Password cannot exceed 128 characters.')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter.')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter.')
  .regex(/[0-9]/, 'Password must contain at least one number.')
  .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character (!@#$%^&* etc.).');

export const registerRequestSchema = z
  .object({
    username: usernameSchema,
    password: passwordSchema,
    confirmPassword: z.string(),
    fullName: z.string().trim().min(2).max(80).optional(),
    department: z.string().trim().min(2).max(60).optional(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match.',
    path: ['confirmPassword'],
  });

export const loginRequestSchema = z.object({
  username: z.string().trim().min(1, 'Username is required.'),
  password: z.string().min(1, 'Password is required.'),
});

export const verify2FARequestSchema = z.object({
  preAuthToken: z.string().min(10, 'Pre-authentication token is required.'),
  code: z
    .string()
    .trim()
    .min(6, 'Enter a 6-digit authenticator code or recovery code.')
    .max(20, 'Invalid 2FA code length.'),
});

export const enable2FARequestSchema = z.object({
  code: z
    .string()
    .trim()
    .regex(/^\d{6}$/, 'Authenticator verification code must be a 6-digit number.'),
});

export const disable2FARequestSchema = z.object({
  password: z.string().min(1, 'Current password is required to disable 2FA.'),
  code: z.string().trim().min(6, 'Enter a 6-digit authenticator code or recovery code.'),
});

export const changePasswordRequestSchema = z
  .object({
    currentPassword: z.string().min(1, 'Current password is required.'),
    newPassword: passwordSchema,
    confirmNewPassword: z.string(),
  })
  .refine((data) => data.newPassword === data.confirmNewPassword, {
    message: 'New passwords do not match.',
    path: ['confirmNewPassword'],
  });

export const updateRoleRequestSchema = z.object({
  role: z.enum(['USER', 'ADMIN']),
});

export const updateStatusRequestSchema = z.object({
  status: z.enum(['ACTIVE', 'DISABLED']),
});

export const createSchoolNoticeSchema = z.object({
  title: z.string().trim().min(3, 'Title must be at least 3 characters.').max(120),
  category: z.enum(['ACADEMIC', 'SECURITY', 'ADMISSIONS', 'EXAMINATIONS', 'GENERAL']),
  content: z.string().trim().min(10, 'Content must be at least 10 characters.').max(2000),
  visibility: z.enum(['PUBLIC', 'AUTHENTICATED_ONLY', 'ADMIN_ONLY']).default('PUBLIC'),
});

/**
 * Strips all sensitive cryptographic fields (`passwordHash`, `totpSecretEncrypted`,
 * `pendingTotpSecretEncrypted`, lockout counters) before sending a user object to clients.
 */
export function toSafeUserDTO(user: UserDocument): SafeUserDTO {
  return {
    id: user.id,
    username: user.username,
    fullName: user.fullName,
    department: user.department,
    studentOrStaffId: user.studentOrStaffId,
    role: user.role,
    status: user.status,
    twoFactorEnabled: user.twoFactorEnabled,
    lastLoginAt: user.lastLoginAt,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

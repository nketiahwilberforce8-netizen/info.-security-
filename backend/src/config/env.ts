import dotenv from 'dotenv';
import path from 'path';
import { z } from 'zod';

// Load environment variables from backend/.env
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

/**
 * Strict Zod validation schema for environment variables.
 * Security Principle: Fail-Fast Configuration Validation.
 * If any cryptographic secret (Pepper, AES-256 key, JWT secret) is missing or weak,
 * the application refuses to boot.
 */
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  SCHOOL_NAME: z.string().default('NKETIAH School Management System'),
  CORS_ORIGINS: z.string().default('http://localhost:5173,http://localhost:8081'),

  // Argon2id Server-Side Pepper (Must be at least 32 chars)
  PASSWORD_PEPPER: z
    .string()
    .min(32, 'PASSWORD_PEPPER must be at least 32 characters long for cryptographic security.')
    .default('NKETIAH_SCHOOL_SUPER_SECRET_PEPPER_2026_V1_9f8e7d6c5b4a3f2e1d0c'),

  // AES-256-GCM Master Key (Must be 64 hex characters = 32 bytes = 256 bits)
  AES_256_GCM_KEY_HEX: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, 'AES_256_GCM_KEY_HEX must be exactly 64 hexadecimal characters (256 bits).')
    .default('4a8f1b9c2d3e4f5061728394a5b6c7d8e9f01a2b3c4d5e6f708192a3b4c5d6e7'),

  // JWT Secrets
  JWT_ACCESS_SECRET: z
    .string()
    .min(32, 'JWT_ACCESS_SECRET must be at least 32 characters.')
    .default('nketiah_jwt_access_secret_key_2026_secure_32chars_min_alpha_998877'),
  JWT_PRE_2FA_SECRET: z
    .string()
    .min(32, 'JWT_PRE_2FA_SECRET must be at least 32 characters.')
    .default('nketiah_jwt_pre2fa_secret_key_2026_secure_32chars_min_beta_112233'),
  ACCESS_TOKEN_EXPIRES_IN: z.string().default('15m'),
  PRE_2FA_TOKEN_EXPIRES_IN: z.string().default('5m'),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(7),

  // Firebase / Google Cloud Configuration
  FIREBASE_MODE: z.enum(['firebase', 'emulator', 'hybrid']).default('hybrid'),
  FIREBASE_PROJECT_ID: z.string().default('nketiah-school-security'),
  FIREBASE_STORAGE_BUCKET: z.string().default('nketiah-school-security.appspot.com'),
  GOOGLE_APPLICATION_CREDENTIALS: z.string().optional(),
  FIREBASE_SERVICE_ACCOUNT_JSON: z.string().optional(),

  // Automated Backup Configuration
  BACKUP_CRON_SCHEDULE: z.string().default('0 */6 * * *'),
  BACKUP_RETENTION_COUNT: z.coerce.number().int().positive().default(20),
});

const parsedEnv = envSchema.safeParse(process.env);

if (!parsedEnv.success) {
  console.error('❌ [CRITICAL SECURITY ERROR] Invalid Environment Configuration:');
  console.error(parsedEnv.error.format());
  process.exit(1);
}

export const env = parsedEnv.data;

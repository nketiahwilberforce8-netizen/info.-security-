import rateLimit from 'express-rate-limit';
import { env } from '../config/env';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - BRUTE-FORCE & RATE LIMITING MIDDLEWARE
 * ============================================================================
 *
 * Protects authentication and 2FA endpoints against automated password spraying,
 * credential stuffing, and TOTP brute-force attacks.
 */

const isTestEnv = env.NODE_ENV === 'test';

export const generalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isTestEnv ? 1000 : 250,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests from this IP address. Please wait 15 minutes and try again.',
  },
});

export const strictAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: isTestEnv ? 100 : 15, // Strict limit on login & 2FA verification
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many authentication attempts from this IP. Please try again after 15 minutes.',
  },
});

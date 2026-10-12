import argon2 from 'argon2';
import crypto from 'crypto';
import { env } from '../config/env';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - ARGON2ID + SALT + PEPPER SERVICE
 * ============================================================================
 *
 * CYBERSECURITY TEACHING NOTES:
 * 1. Why Hashing (Not Encryption)?
 *    Passwords must NEVER be reversible. Hashing is a one-way mathematical
 *    transformation. Even a system administrator cannot recover a user's password.
 *
 * 2. Why Salt?
 *    Each password receives a unique 128-bit (16-byte) cryptographically random
 *    salt via `crypto.randomBytes(16)`. This defeats precomputed Rainbow Tables
 *    and ensures two users with the same password have completely different hashes.
 *
 * 3. Why Server-Side Pepper?
 *    A salt is stored alongside the hash in the Firestore database. What if an
 *    attacker dumps the Firestore database? By first combining the plaintext
 *    password with `env.PASSWORD_PEPPER` (stored ONLY in server environment
 *    variables, never in Firestore) via HMAC-SHA256, stolen database hashes
 *    cannot be brute-forced without also stealing the server's secret pepper.
 *
 * 4. Why Argon2id?
 *    Argon2id is the OWASP #1 recommended password hashing algorithm. It is
 *    memory-hard (64 MiB RAM per hash), making GPU/ASIC cracking prohibitively slow,
 *    while resisting side-channel timing attacks.
 */

const ARGON2_OPTIONS: argon2.Options = {
  type: argon2.argon2id, // Hybrid mode: side-channel resistance + GPU resistance
  memoryCost: 65536,     // 64 MiB memory cost (OWASP recommended)
  timeCost: 3,           // 3 iterations
  parallelism: 4,        // 4 parallel threads
  hashLength: 32,        // 256-bit output digest
};

/**
 * Combines the raw password with the secret server-side Pepper using HMAC-SHA256.
 * Using HMAC-SHA256 avoids null-byte truncation issues and produces a fixed-length
 * peppered input for Argon2id.
 */
export function applyServerPepper(plainPassword: string, customPepper?: string): string {
  const pepperSecret = customPepper ?? env.PASSWORD_PEPPER;
  return crypto.createHmac('sha256', pepperSecret).update(plainPassword, 'utf8').digest('hex');
}

/**
 * Hashes a plaintext password using:
 * 1. Server-side Pepper (HMAC-SHA256)
 * 2. Unique 16-byte cryptographic Salt
 * 3. Argon2id memory-hard key derivation
 */
export async function hashPassword(plainPassword: string): Promise<string> {
  const pepperedPassword = applyServerPepper(plainPassword);
  const uniqueSalt = crypto.randomBytes(16); // Explicit 128-bit unique salt per password

  const encodedHash = await argon2.hash(pepperedPassword, {
    ...ARGON2_OPTIONS,
    salt: uniqueSalt,
  });

  return encodedHash;
}

/**
 * Verifies a plaintext password against a stored Argon2id hash.
 * Includes constant-time verification inside Argon2.
 */
export async function verifyPassword(
  plainPassword: string,
  storedArgon2Hash: string,
  customPepper?: string
): Promise<boolean> {
  try {
    const pepperedPassword = applyServerPepper(plainPassword, customPepper);
    return await argon2.verify(storedArgon2Hash, pepperedPassword);
  } catch {
    return false;
  }
}

// Pre-computed dummy hash used when a username does not exist to prevent timing enumeration attacks
let cachedDummyHash: string | null = null;

export async function performDummyPasswordVerify(plainPassword: string): Promise<void> {
  if (!cachedDummyHash) {
    cachedDummyHash = await hashPassword('DUMMY_ANTITIMING_PASSWORD_NKETIAH_2026!');
  }
  await verifyPassword(plainPassword, cachedDummyHash);
}

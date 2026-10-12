import crypto from 'crypto';
import { env } from '../config/env';
import { AesGcmEncryptedPayload } from '../types/models';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - AES-256-GCM ENCRYPTION SERVICE
 * ============================================================================
 *
 * CYBERSECURITY TEACHING NOTES:
 * 1. Symmetric Cryptography:
 *    Uses the same 256-bit (32-byte) secret key for both encryption and decryption.
 *    The key is stored strictly in `env.AES_256_GCM_KEY_HEX` outside the database.
 *
 * 2. Why AES-256-GCM?
 *    - AES-256: 256-bit key strength approved for TOP SECRET information by NIST.
 *    - GCM (Galois/Counter Mode): Provides BOTH Confidentiality (encryption) AND
 *      Integrity/Authenticity (via a 128-bit Authentication Tag).
 *    - If an attacker alters even 1 bit of the ciphertext or IV in Firestore,
 *      `decipher.final()` throws an authentication error and refuses to output data!
 *
 * 3. Initialization Vector (IV / Nonce):
 *    Every single encryption operation generates a fresh, cryptographically random
 *    12-byte (96-bit) IV (`crypto.randomBytes(12)`). Reusing an IV with the same
 *    key in GCM is catastrophic, so we NEVER reuse IVs.
 */

const ALGORITHM = 'aes-256-gcm';
const IV_BYTE_LENGTH = 12;       // NIST recommended 96-bit IV for AES-GCM
const AUTH_TAG_BYTE_LENGTH = 16; // 128-bit Authentication Tag

function getMasterKeyBuffer(customKeyHex?: string): Buffer {
  const hex = customKeyHex ?? env.AES_256_GCM_KEY_HEX;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('Invalid AES-256 key: must be 64 hexadecimal characters (32 bytes / 256 bits).');
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Encrypts any UTF-8 plaintext string (e.g., a TOTP Secret or Database Backup JSON)
 * using AES-256-GCM with a unique 96-bit IV and 128-bit authentication tag.
 */
export function encryptAes256Gcm(
  plaintext: string,
  customKeyHex?: string
): AesGcmEncryptedPayload {
  const key = getMasterKeyBuffer(customKeyHex);
  const iv = crypto.randomBytes(IV_BYTE_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_BYTE_LENGTH,
  });

  const encryptedBuffer = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return {
    algorithm: 'aes-256-gcm',
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    ciphertextHex: encryptedBuffer.toString('hex'),
    keyVersion: 1,
  };
}

/**
 * Decrypts and authenticates an AES-256-GCM payload.
 * Throws a cryptographic error if the key is wrong or if the ciphertext, IV,
 * or authentication tag has been tampered with.
 */
export function decryptAes256Gcm(
  payload: AesGcmEncryptedPayload,
  customKeyHex?: string
): string {
  if (!payload || payload.algorithm !== 'aes-256-gcm') {
    throw new Error('Unsupported or malformed encryption payload.');
  }

  const key = getMasterKeyBuffer(customKeyHex);
  const iv = Buffer.from(payload.ivHex, 'hex');
  const authTag = Buffer.from(payload.authTagHex, 'hex');
  const ciphertext = Buffer.from(payload.ciphertextHex, 'hex');

  if (iv.length !== IV_BYTE_LENGTH) {
    throw new Error('Invalid AES-GCM IV length.');
  }
  if (authTag.length !== AUTH_TAG_BYTE_LENGTH) {
    throw new Error('Invalid AES-GCM Authentication Tag length.');
  }

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_BYTE_LENGTH,
  });

  decipher.setAuthTag(authTag);

  const decryptedBuffer = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decryptedBuffer.toString('utf8');
}

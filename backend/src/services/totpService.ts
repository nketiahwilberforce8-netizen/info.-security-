import crypto from 'crypto';
import https from 'https';
import QRCode from 'qrcode';
import { env } from '../config/env';
import { RecoveryCodeEntry } from '../types/models';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - RFC 6238 TOTP & RECOVERY CODE SERVICE
 * ============================================================================
 *
 * Compatible with Google Authenticator, Microsoft Authenticator, Authy, 1Password.
 * Implements RFC 4648 Base32, RFC 4226 HOTP Dynamic Truncation, and RFC 6238 TOTP.
 *
 * CLOCK-DRIFT PROTECTION (PC Clock vs. Smartphone Real-World Time):
 * If a student's Windows PC system clock is out of sync with real-world UTC time
 * (e.g., PC clock set to a different month/year than the smartphone), TOTP codes
 * generated on a phone would normally mismatch `Date.now()`.
 * To solve this professionally:
 * 1. We automatically detect the offset between `Date.now()` and real-world UTC
 *    time via an HTTPS `Date` header probe (`networkTimeOffsetMs`).
 * 2. `verifyTotpCode` checks BOTH the PC's local clock (`Date.now()`) AND the
 *    real-world network UTC clock (`Date.now() + networkTimeOffsetMs`)!
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const TOTP_PERIOD_SECONDS = 30;
const TOTP_DIGITS = 6;

let networkTimeOffsetMs = 0;

/**
 * Probes a trusted HTTPS server's `Date` header to detect if the local Windows PC
 * clock is out of sync with real-world smartphone time.
 */
export function syncNetworkTimeOffset(): void {
  try {
    const req = https.request(
      'https://www.google.com',
      { method: 'HEAD', timeout: 3500 },
      (res) => {
        const dateHeader = res.headers.date;
        if (dateHeader) {
          const networkUtcMs = new Date(dateHeader).getTime();
          if (!Number.isNaN(networkUtcMs)) {
            networkTimeOffsetMs = networkUtcMs - Date.now();
            if (Math.abs(networkTimeOffsetMs) > 60000) {
              console.log(
                `🕒 [TOTP Clock Sync] Detected PC clock offset of ${Math.round(
                  networkTimeOffsetMs / 1000 / 60
                )} minutes vs real-world UTC. Both PC time and Smartphone UTC are now accepted!`
              );
            }
          }
        }
      }
    );
    req.on('error', () => {
      // Offline mode: rely on local PC clock
    });
    req.end();
  } catch {
    // Ignore if offline
  }
}

// Run initial clock sync probe on startup
syncNetworkTimeOffset();

export function getEffectivePhoneTimestampMs(): number {
  return Date.now() + networkTimeOffsetMs;
}

/**
 * Encodes a Buffer into RFC 4648 Base32 string (used by Authenticator apps).
 */
export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decodes an RFC 4648 Base32 string back into a raw Buffer.
 */
export function base32Decode(base32Str: string): Buffer {
  const cleaned = base32Str.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character found: ${cleaned[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Generates a fresh 160-bit (20-byte) cryptographically random TOTP secret in Base32.
 */
export function generateTotpSecret(): string {
  const randomBytes = crypto.randomBytes(20);
  return base32Encode(randomBytes);
}

/**
 * Generates an RFC 6238 6-digit TOTP token for a given timestamp and Base32 secret.
 */
export function generateTotpCode(
  base32Secret: string,
  timestampMs: number = Date.now()
): string {
  const secretBytes = base32Decode(base32Secret);
  const counter = Math.floor(timestampMs / 1000 / TOTP_PERIOD_SECONDS);

  // Convert 64-bit integer counter to 8-byte big-endian buffer
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

  // RFC 4226 HMAC-SHA1 calculation
  const hmac = crypto.createHmac('sha1', secretBytes).update(counterBuffer).digest();

  // Dynamic truncation
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binaryCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binaryCode % Math.pow(10, TOTP_DIGITS);
  return otp.toString().padStart(TOTP_DIGITS, '0');
}

/**
 * Verifies a 6-digit TOTP token against a Base32 secret.
 * Checks BOTH:
 * 1. The local PC clock (`timestampMs`, +/- 2 steps)
 * 2. The real-world smartphone UTC clock (`Date.now() + networkTimeOffsetMs`, +/- 2 steps)
 * Uses constant-time comparison (`crypto.timingSafeEqual`) to prevent timing attacks.
 */
export function verifyTotpCode(
  token: string,
  base32Secret: string,
  timestampMs: number = Date.now(),
  windowSteps: number = 2
): boolean {
  const cleanedToken = token.trim().replace(/\s+/g, '');
  if (!/^\d{6}$/.test(cleanedToken)) {
    return false;
  }

  const candidateBuffer = Buffer.from(cleanedToken, 'utf8');

  const candidateTimestamps = [timestampMs];
  if (networkTimeOffsetMs !== 0) {
    candidateTimestamps.push(Date.now() + networkTimeOffsetMs);
  }

  for (const baseTime of candidateTimestamps) {
    for (let errorWindow = -windowSteps; errorWindow <= windowSteps; errorWindow++) {
      const checkTime = baseTime + errorWindow * TOTP_PERIOD_SECONDS * 1000;
      const expectedCode = generateTotpCode(base32Secret, checkTime);
      const expectedBuffer = Buffer.from(expectedCode, 'utf8');

      if (
        candidateBuffer.length === expectedBuffer.length &&
        crypto.timingSafeEqual(candidateBuffer, expectedBuffer)
      ) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Builds the standard `otpauth://totp/...` URI and renders a Data URL QR code image
 * for scanning in Google Authenticator / Microsoft Authenticator.
 */
export async function generateTotpQrCode(
  username: string,
  base32Secret: string
): Promise<{
  otpauthUrl: string;
  qrCodeDataUrl: string;
}> {
  const issuer = 'NKETIAH School';
  const label = encodeURIComponent(`${issuer}:${username}`);
  const encodedIssuer = encodeURIComponent(issuer);

  const otpauthUrl = `otpauth://totp/${label}?secret=${base32Secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
  const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl, {
    width: 280,
    margin: 2,
    color: {
      dark: '#0f172a',
      light: '#ffffff',
    },
  });

  return { otpauthUrl, qrCodeDataUrl };
}

/**
 * Normalizes and hashes a recovery code with the server-side pepper so recovery
 * codes are never stored in plaintext in Firestore.
 */
export function hashRecoveryCode(rawCode: string): string {
  const normalized = rawCode.trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  return crypto
    .createHmac('sha256', env.PASSWORD_PEPPER)
    .update(`RECOVERY:${normalized}`, 'utf8')
    .digest('hex');
}

/**
 * Generates 8 one-time recovery codes (e.g., "NKET-4A9F-82C1").
 * Returns both the plaintext codes (shown ONCE to the user) and the hashed entries for Firestore.
 */
export function generateRecoveryCodes(count: number = 8): {
  plainCodes: string[];
  hashedEntries: RecoveryCodeEntry[];
} {
  const plainCodes: string[] = [];
  const hashedEntries: RecoveryCodeEntry[] = [];

  for (let i = 0; i < count; i++) {
    const part1 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const part2 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const code = `NKET-${part1}-${part2}`;
    plainCodes.push(code);
    hashedEntries.push({
      codeHash: hashRecoveryCode(code),
      used: false,
      usedAt: null,
    });
  }

  return { plainCodes, hashedEntries };
}

import crypto from 'crypto';
import { firestoreRepo } from '../config/firebase';
import { AuditEventType, AuditLogDocument } from '../types/models';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - SECURITY AUDIT LOGGING SERVICE
 * ============================================================================
 *
 * TEACHING NOTE ON SECURITY AUDIT LOGGING:
 * What SHOULD be logged:
 * - Who performed an action (`actorUserId`, `actorUsername`)
 * - What action occurred (`eventType`, `severity`, `details`)
 * - When it occurred (`createdAt` ISO timestamp)
 * - Where it originated (`ipAddress`, `userAgent`)
 * - Which account/resource was affected (`targetUserId`, `targetUsername`)
 *
 * What MUST NEVER be logged:
 * - Plaintext passwords or password hashes
 * - Server-side Pepper or AES-256-GCM encryption keys
 * - TOTP secrets or recovery codes
 * - Raw JWTs or Refresh Tokens
 */

export interface CreateAuditLogInput {
  eventType: AuditEventType;
  severity?: 'INFO' | 'WARNING' | 'CRITICAL';
  actorUserId?: string | null;
  actorUsername?: string | null;
  targetUserId?: string | null;
  targetUsername?: string | null;
  ipAddress?: string;
  userAgent?: string;
  details: string;
  metadata?: Record<string, string | number | boolean | null>;
}

const FORBIDDEN_LOG_KEYS = [
  'password',
  'passwordHash',
  'pepper',
  'totpSecret',
  'totpSecretEncrypted',
  'recoveryCode',
  'accessToken',
  'refreshToken',
  'aesKey',
];

function sanitizeMetadata(
  meta?: Record<string, string | number | boolean | null>
): Record<string, string | number | boolean | null> | undefined {
  if (!meta) return undefined;
  const sanitized: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(meta)) {
    const lowerKey = key.toLowerCase();
    if (FORBIDDEN_LOG_KEYS.some((forbidden) => lowerKey.includes(forbidden.toLowerCase()))) {
      sanitized[key] = '[REDACTED_SENSITIVE]';
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

export async function recordAuditLog(input: CreateAuditLogInput): Promise<AuditLogDocument> {
  const id = `aud_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  const doc: AuditLogDocument = {
    id,
    eventType: input.eventType,
    severity: input.severity ?? 'INFO',
    actorUserId: input.actorUserId ?? null,
    actorUsername: input.actorUsername ?? null,
    targetUserId: input.targetUserId ?? null,
    targetUsername: input.targetUsername ?? null,
    ipAddress: input.ipAddress ?? '127.0.0.1',
    userAgent: input.userAgent ?? 'System',
    details: input.details,
    metadata: sanitizeMetadata(input.metadata),
    createdAt: new Date().toISOString(),
  };

  await firestoreRepo.setDoc('auditLogs', id, doc);
  return doc;
}

export async function listAuditLogs(limitCount: number = 100): Promise<AuditLogDocument[]> {
  const all = await firestoreRepo.listDocs('auditLogs');
  return all
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, limitCount);
}

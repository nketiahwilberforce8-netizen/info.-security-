/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - SECURE WEB API CLIENT
 * ============================================================================
 *
 * SECURITY PRINCIPLE:
 * We store the short-lived JWT `accessToken` ONLY in JavaScript memory (`inMemoryAccessToken`),
 * NEVER in `window.localStorage` or `window.sessionStorage` where XSS scripts could steal it.
 * The Refresh Token is managed via an `HttpOnly; SameSite=Strict` cookie (`credentials: 'include'`).
 */

export interface SafeUser {
  id: string;
  username: string;
  fullName: string;
  department: string;
  studentOrStaffId: string;
  role: 'GUEST' | 'USER' | 'ADMIN';
  status: 'ACTIVE' | 'DISABLED';
  twoFactorEnabled: boolean;
  lastLoginAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface SchoolNotice {
  id: string;
  title: string;
  category: 'ACADEMIC' | 'SECURITY' | 'ADMISSIONS' | 'EXAMINATIONS' | 'GENERAL';
  content: string;
  visibility: 'PUBLIC' | 'AUTHENTICATED_ONLY' | 'ADMIN_ONLY';
  authorUsername: string;
  authorRole: string;
  createdAt: string;
}

export interface AuditLogEntry {
  id: string;
  eventType: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  actorUsername: string | null;
  targetUsername: string | null;
  ipAddress: string;
  details: string;
  createdAt: string;
}

export interface BackupEntry {
  id: string;
  backupId: string;
  filename: string;
  triggerType: 'AUTOMATED_CRON' | 'MANUAL_CLI' | 'ADMIN_API';
  status: 'SUCCESS' | 'FAILED' | 'RESTORED';
  storageLocation: string;
  sizeBytes: number;
  checksumSha256: string;
  encryptionAlgorithm: string;
  collectionCounts: {
    users: number;
    sessions: number;
    recoveryCodes: number;
    schoolNotices: number;
    auditLogs: number;
  };
  triggeredByUsername: string;
  createdAt: string;
  restoredAt: string | null;
}

let inMemoryAccessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  inMemoryAccessToken = token;
}

export function getAccessToken(): string | null {
  return inMemoryAccessToken;
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api';

export async function apiRequest<T = any>(
  endpoint: string,
  options: RequestInit = {},
  retryOn401: boolean = true
): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!headers.has('Content-Type') && options.body) {
    headers.set('Content-Type', 'application/json');
  }
  if (inMemoryAccessToken) {
    headers.set('Authorization', `Bearer ${inMemoryAccessToken}`);
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
    credentials: 'include', // Sends HttpOnly refresh token cookie automatically
  });

  if (response.status === 401 && retryOn401 && !endpoint.startsWith('/auth/')) {
    // Attempt silent token refresh using HttpOnly cookie
    const refreshed = await trySilentRefresh();
    if (refreshed) {
      return apiRequest<T>(endpoint, options, false);
    }
  }

  const json = await response.json().catch(() => ({
    success: false,
    error: 'Unexpected server response.',
  }));

  if (!response.ok || json.success === false) {
    throw new Error(json.error || `Request failed with status ${response.status}`);
  }

  return json;
}

export async function trySilentRefresh(): Promise<SafeUser | null> {
  try {
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
    });
    if (!res.ok) {
      setAccessToken(null);
      return null;
    }
    const json = await res.json();
    if (json.success && json.data?.accessToken) {
      setAccessToken(json.data.accessToken);
      return json.data.user as SafeUser;
    }
    return null;
  } catch {
    setAccessToken(null);
    return null;
  }
}

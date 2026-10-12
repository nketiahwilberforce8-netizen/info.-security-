import { mobileTokenStorage } from '../storage/secureTokenStore';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - EXPO MOBILE API CLIENT
 * ============================================================================
 *
 * Connects to the EXACT SAME central Node.js Backend API (`http://localhost:4000/api`)
 * as the React Web application. Automatically attaches the Bearer Access Token
 * from `expo-secure-store` and rotates Refresh Tokens seamlessly.
 */

// For physical devices on the same Wi-Fi, replace localhost with your PC's LAN IP (e.g. http://192.168.1.100:4000/api)
export const MOBILE_API_BASE_URL = 'http://localhost:4000/api';

export interface MobileSafeUser {
  id: string;
  username: string;
  fullName: string;
  department: string;
  studentOrStaffId: string;
  role: 'GUEST' | 'USER' | 'ADMIN';
  status: 'ACTIVE' | 'DISABLED';
  twoFactorEnabled: boolean;
}

export async function mobileApiRequest<T = any>(
  endpoint: string,
  options: RequestInit = {},
  retryOn401: boolean = true
): Promise<T> {
  const accessToken = await mobileTokenStorage.getAccessToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${MOBILE_API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401 && retryOn401 && !endpoint.startsWith('/auth/')) {
    const refreshed = await tryMobileTokenRefresh();
    if (refreshed) {
      return mobileApiRequest<T>(endpoint, options, false);
    }
  }

  const json = await response.json().catch(() => ({
    success: false,
    error: 'Network or server error communicating with NKETIAH API.',
  }));

  if (!response.ok || json.success === false) {
    throw new Error(json.error || `HTTP Error ${response.status}`);
  }

  return json;
}

export async function tryMobileTokenRefresh(): Promise<MobileSafeUser | null> {
  const refreshToken = await mobileTokenStorage.getRefreshToken();
  if (!refreshToken) return null;

  try {
    const response = await fetch(`${MOBILE_API_BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });

    if (!response.ok) {
      await mobileTokenStorage.clearTokens();
      return null;
    }

    const json = await response.json();
    if (json.success && json.data?.accessToken && json.data?.refreshToken) {
      await mobileTokenStorage.saveTokens(
        json.data.accessToken,
        json.data.refreshToken
      );
      return json.data.user as MobileSafeUser;
    }

    return null;
  } catch {
    return null;
  }
}

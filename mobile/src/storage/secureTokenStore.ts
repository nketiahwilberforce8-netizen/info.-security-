import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - HARDWARE-BACKED MOBILE SECURE STORAGE
 * ============================================================================
 *
 * TEACHING NOTE:
 * Why does mobile token storage differ from web browser storage?
 * - Web browsers use an in-memory Access Token + `HttpOnly; SameSite=Strict`
 *   Refresh Token Cookie because `window.localStorage` is vulnerable to XSS.
 * - Mobile apps (iOS & Android) do not have a browser cookie jar. Instead,
 *   `expo-secure-store` encrypts tokens using the device's hardware-backed
 *   secure enclave:
 *   * iOS     : Keychain Services (`kSecAttrAccessibleAfterFirstUnlock`)
 *   * Android : Android Keystore + EncryptedSharedPreferences (AES-256-GCM)
 */

const ACCESS_TOKEN_KEY = 'nketiah_mobile_access_token';
const REFRESH_TOKEN_KEY = 'nketiah_mobile_refresh_token';

// In-memory fallback when running Expo in a web browser preview
const memoryFallback: Record<string, string | null> = {};

async function setSecureItem(key: string, value: string | null): Promise<void> {
  memoryFallback[key] = value;
  if (Platform.OS === 'web') return;
  try {
    if (value === null) {
      await SecureStore.deleteItemAsync(key);
    } else {
      await SecureStore.setItemAsync(key, value);
    }
  } catch {
    // Fallback to memory if SecureStore unavailable on simulator
  }
}

async function getSecureItem(key: string): Promise<string | null> {
  if (Platform.OS === 'web') {
    return memoryFallback[key] ?? null;
  }
  try {
    return (await SecureStore.getItemAsync(key)) ?? memoryFallback[key] ?? null;
  } catch {
    return memoryFallback[key] ?? null;
  }
}

export const mobileTokenStorage = {
  async saveTokens(accessToken: string, refreshToken: string): Promise<void> {
    await setSecureItem(ACCESS_TOKEN_KEY, accessToken);
    await setSecureItem(REFRESH_TOKEN_KEY, refreshToken);
  },

  async getAccessToken(): Promise<string | null> {
    return getSecureItem(ACCESS_TOKEN_KEY);
  },

  async getRefreshToken(): Promise<string | null> {
    return getSecureItem(REFRESH_TOKEN_KEY);
  },

  async clearTokens(): Promise<void> {
    await setSecureItem(ACCESS_TOKEN_KEY, null);
    await setSecureItem(REFRESH_TOKEN_KEY, null);
  },
};

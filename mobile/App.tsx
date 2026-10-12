import React, { useEffect, useState } from 'react';
import {
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
  Image,
  ActivityIndicator,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import {
  mobileApiRequest,
  MobileSafeUser,
  tryMobileTokenRefresh,
} from './src/api/mobileClient';
import { mobileTokenStorage } from './src/storage/secureTokenStore';

type MobileScreen =
  | 'WELCOME'
  | 'LOGIN'
  | 'VERIFY_2FA'
  | 'REGISTER'
  | 'DASHBOARD'
  | 'SECURITY_2FA'
  | 'ADMIN_PANEL';

export default function App() {
  const [screen, setScreen] = useState<MobileScreen>('WELCOME');
  const [user, setUser] = useState<MobileSafeUser | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(
    null
  );

  // Public Notices
  const [notices, setNotices] = useState<any[]>([]);

  // Auth Inputs
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [preAuthToken, setPreAuthToken] = useState<string | null>(null);
  const [twoFactorCode, setTwoFactorCode] = useState('');

  // 2FA Setup State
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [manualKey, setManualKey] = useState<string | null>(null);
  const [setupCode, setSetupCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [disablePass, setDisablePass] = useState('');
  const [disableOtp, setDisableOtp] = useState('');

  // Admin State
  const [adminUsers, setAdminUsers] = useState<MobileSafeUser[]>([]);
  const [adminBackups, setAdminBackups] = useState<any[]>([]);

  const loadOverview = async () => {
    try {
      const res = await mobileApiRequest('/school/overview');
      setNotices(res.data.notices || []);
    } catch {
      // Offline or server not started yet
    }
  };

  useEffect(() => {
    (async () => {
      const restored = await tryMobileTokenRefresh();
      if (restored) {
        setUser(restored);
        setScreen('DASHBOARD');
      }
      await loadOverview();
    })();
  }, []);

  const handleLogin = async () => {
    setMessage(null);
    setLoading(true);
    try {
      const res = await mobileApiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });

      if (res.requiresTwoFactor) {
        setPreAuthToken(res.data.preAuthToken);
        setScreen('VERIFY_2FA');
        setMessage({
          type: 'ok',
          text: 'Password verified! Enter 6-digit TOTP or Recovery Code.',
        });
      } else {
        await mobileTokenStorage.saveTokens(
          res.data.accessToken,
          res.data.refreshToken
        );
        setUser(res.data.user);
        setPassword('');
        setScreen('DASHBOARD');
        await loadOverview();
      }
    } catch (err) {
      setMessage({ type: 'err', text: (err as Error).message });
    } finally {
      setLoading(false);
    }
  };

  const handleVerify2FA = async () => {
    if (!preAuthToken) return;
    setMessage(null);
    setLoading(true);
    try {
      const res = await mobileApiRequest('/auth/verify-2fa', {
        method: 'POST',
        body: JSON.stringify({ preAuthToken, code: twoFactorCode }),
      });
      await mobileTokenStorage.saveTokens(
        res.data.accessToken,
        res.data.refreshToken
      );
      setUser(res.data.user);
      setPreAuthToken(null);
      setTwoFactorCode('');
      setPassword('');
      setScreen('DASHBOARD');
      setMessage({ type: 'ok', text: res.message });
    } catch (err) {
      setMessage({ type: 'err', text: (err as Error).message });
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    setMessage(null);
    setLoading(true);
    try {
      const res = await mobileApiRequest('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          username,
          fullName,
          department: 'Information Technology',
          password,
          confirmPassword,
        }),
      });
      await mobileTokenStorage.saveTokens(
        res.data.accessToken,
        res.data.refreshToken
      );
      setUser(res.data.user);
      setPassword('');
      setConfirmPassword('');
      setScreen('DASHBOARD');
      setMessage({ type: 'ok', text: 'Welcome to NKETIAH Mobile!' });
    } catch (err) {
      setMessage({ type: 'err', text: (err as Error).message });
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    const refreshToken = await mobileTokenStorage.getRefreshToken();
    try {
      await mobileApiRequest('/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refreshToken }),
      });
    } catch {
      // Ignore
    }
    await mobileTokenStorage.clearTokens();
    setUser(null);
    setScreen('WELCOME');
    setMessage({ type: 'ok', text: 'Signed out and cleared Expo SecureStore.' });
  };

  const handleStart2FASetup = async () => {
    setMessage(null);
    try {
      const res = await mobileApiRequest('/auth/2fa/setup', { method: 'POST' });
      setQrDataUrl(res.data.qrCodeDataUrl);
      setManualKey(res.data.manualEntryKey);
    } catch (err) {
      setMessage({ type: 'err', text: (err as Error).message });
    }
  };

  const handleEnable2FA = async () => {
    setMessage(null);
    try {
      const res = await mobileApiRequest('/auth/2fa/enable', {
        method: 'POST',
        body: JSON.stringify({ code: setupCode }),
      });
      setUser(res.data.user);
      setRecoveryCodes(res.data.recoveryCodes);
      setQrDataUrl(null);
      setSetupCode('');
      setMessage({ type: 'ok', text: res.message });
    } catch (err) {
      setMessage({ type: 'err', text: (err as Error).message });
    }
  };

  const handleDisable2FA = async () => {
    setMessage(null);
    try {
      const res = await mobileApiRequest('/auth/2fa/disable', {
        method: 'POST',
        body: JSON.stringify({ password: disablePass, code: disableOtp }),
      });
      setUser(res.data.user);
      setDisablePass('');
      setDisableOtp('');
      setRecoveryCodes(null);
      setMessage({ type: 'ok', text: res.message });
    } catch (err) {
      setMessage({ type: 'err', text: (err as Error).message });
    }
  };

  const loadAdminData = async () => {
    try {
      const [uRes, bRes] = await Promise.all([
        mobileApiRequest('/admin/users'),
        mobileApiRequest('/admin/backups'),
      ]);
      setAdminUsers(uRes.data.users || []);
      setAdminBackups(bRes.data.backups || []);
    } catch (err) {
      setMessage({ type: 'err', text: (err as Error).message });
    }
  };

  const triggerMobileBackup = async () => {
    try {
      const res = await mobileApiRequest('/admin/backups', { method: 'POST' });
      setMessage({ type: 'ok', text: res.message });
      await loadAdminData();
    } catch (err) {
      setMessage({ type: 'err', text: (err as Error).message });
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />

      {/* HEADER */}
      <View style={styles.header}>
        <View>
          <Text style={styles.schoolTitle}>NKETIAH MOBILE</Text>
          <Text style={styles.subtitle}>
            Role: {user ? user.role : 'GUEST'} • Expo SecureStore
          </Text>
        </View>
        {user && (
          <TouchableOpacity style={styles.logoutBtn} onPress={handleLogout}>
            <Text style={styles.logoutText}>Sign Out</Text>
          </TouchableOpacity>
        )}
      </View>

      <ScrollView contentContainerStyle={styles.scrollBody}>
        {message && (
          <View
            style={[
              styles.banner,
              message.type === 'ok' ? styles.bannerOk : styles.bannerErr,
            ]}
          >
            <Text style={styles.bannerText}>{message.text}</Text>
          </View>
        )}

        {/* SCREEN 1: GUEST WELCOME */}
        {screen === 'WELCOME' && (
          <View style={styles.card}>
            <Text style={styles.heading}>NKETIAH School Management System</Text>
            <Text style={styles.paragraph}>
              Shared Node.js Security Backend serving both React Web and Expo Mobile.
              Protected by Argon2id (Salt + Pepper), TOTP 2FA, AES-256-GCM Encryption,
              and Automated Firestore Backups.
            </Text>

            <TouchableOpacity
              style={styles.primaryBtn}
              onPress={() => setScreen('LOGIN')}
            >
              <Text style={styles.primaryBtnText}>Sign In with Username</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.secondaryBtn}
              onPress={() => setScreen('REGISTER')}
            >
              <Text style={styles.secondaryBtnText}>Register Student Account</Text>
            </TouchableOpacity>

            <Text style={[styles.heading, { marginTop: 18, fontSize: 15 }]}>
              Public School Notices ({notices.length})
            </Text>
            {notices.map((n) => (
              <View key={n.id} style={styles.noticeItem}>
                <Text style={styles.noticeCategory}>{n.category}</Text>
                <Text style={styles.noticeTitle}>{n.title}</Text>
                <Text style={styles.paragraph}>{n.content}</Text>
              </View>
            ))}
          </View>
        )}

        {/* SCREEN 2: LOGIN */}
        {screen === 'LOGIN' && (
          <View style={styles.card}>
            <Text style={styles.heading}>Username + Password Login</Text>
            <Text style={styles.paragraph}>
              No email address required. Tokens are stored in hardware-backed Expo
              SecureStore.
            </Text>

            <View style={{ flexDirection: 'row', gap: 8, marginBottom: 12 }}>
              <TouchableOpacity
                style={[styles.secondaryBtn, { flex: 1, marginTop: 0 }]}
                onPress={() => {
                  setUsername('nketiah_admin');
                  setPassword('Admin@Nketiah2026!');
                }}
              >
                <Text style={styles.secondaryBtnText}>Fill Admin</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.secondaryBtn, { flex: 1, marginTop: 0 }]}
                onPress={() => {
                  setUsername('kwame_student');
                  setPassword('Student@Nketiah2026!');
                }}
              >
                <Text style={styles.secondaryBtnText}>Fill Student</Text>
              </TouchableOpacity>
            </View>

            <TextInput
              style={styles.input}
              placeholder="Username"
              placeholderTextColor="#64748b"
              autoCapitalize="none"
              value={username}
              onChangeText={setUsername}
            />
            <TextInput
              style={styles.input}
              placeholder="Password"
              placeholderTextColor="#64748b"
              secureTextEntry
              value={password}
              onChangeText={setPassword}
            />

            <TouchableOpacity
              style={styles.primaryBtn}
              onPress={handleLogin}
              disabled={loading}
            >
              {loading ? (
                <ActivityIndicator color="#fff" />
              ) : (
                <Text style={styles.primaryBtnText}>Sign In</Text>
              )}
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.secondaryBtn}
              onPress={() => setScreen('WELCOME')}
            >
              <Text style={styles.secondaryBtnText}>Back to Public Portal</Text>
            </TouchableOpacity>
          </View>
        )}

        {/* SCREEN 3: 2FA VERIFICATION */}
        {screen === 'VERIFY_2FA' && (
          <View style={styles.card}>
            <Text style={styles.heading}>Two-Factor Verification (2FA)</Text>
            <Text style={styles.paragraph}>
              Enter your 6-digit Authenticator code or a one-time Recovery Code
              (NKET-XXXX-XXXX).
            </Text>

            <TextInput
              style={styles.input}
              placeholder="123456 or NKET-XXXX-XXXX"
              placeholderTextColor="#64748b"
              autoCapitalize="characters"
              value={twoFactorCode}
              onChangeText={setTwoFactorCode}
            />

            <TouchableOpacity
              style={styles.primaryBtn}
              onPress={handleVerify2FA}
              disabled={loading}
            >
              <Text style={styles.primaryBtnText}>Verify 2FA Code</Text>
            </TouchableOpacity>
          </View>
        )}

        {/* SCREEN 4: REGISTER */}
        {screen === 'REGISTER' && (
          <View style={styles.card}>
            <Text style={styles.heading}>Student / Staff Registration</Text>
            <TextInput
              style={styles.input}
              placeholder="Unique Username"
              placeholderTextColor="#64748b"
              autoCapitalize="none"
              value={username}
              onChangeText={setUsername}
            />
            <TextInput
              style={styles.input}
              placeholder="Full Name"
              placeholderTextColor="#64748b"
              value={fullName}
              onChangeText={setFullName}
            />
            <TextInput
              style={styles.input}
              placeholder="Password (min 8 chars, A-Z, a-z, 0-9, symbol)"
              placeholderTextColor="#64748b"
              secureTextEntry
              value={password}
              onChangeText={setPassword}
            />
            <TextInput
              style={styles.input}
              placeholder="Confirm Password"
              placeholderTextColor="#64748b"
              secureTextEntry
              value={confirmPassword}
              onChangeText={setConfirmPassword}
            />

            <TouchableOpacity
              style={styles.primaryBtn}
              onPress={handleRegister}
              disabled={loading}
            >
              <Text style={styles.primaryBtnText}>Create Account</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.secondaryBtn}
              onPress={() => setScreen('WELCOME')}
            >
              <Text style={styles.secondaryBtnText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        )}

        {/* SCREEN 5: USER DASHBOARD */}
        {screen === 'DASHBOARD' && user && (
          <View style={styles.card}>
            <Text style={styles.badge}>{user.studentOrStaffId}</Text>
            <Text style={styles.heading}>{user.fullName}</Text>
            <Text style={styles.paragraph}>
              @{user.username} • {user.department} • Role: {user.role}
            </Text>
            <Text style={styles.paragraph}>
              2FA Status: {user.twoFactorEnabled ? 'ENABLED (AES-256-GCM)' : 'DISABLED'}
            </Text>

            <TouchableOpacity
              style={styles.primaryBtn}
              onPress={() => setScreen('SECURITY_2FA')}
            >
              <Text style={styles.primaryBtnText}>
                2FA & Security Settings
              </Text>
            </TouchableOpacity>

            {user.role === 'ADMIN' && (
              <TouchableOpacity
                style={[styles.secondaryBtn, { borderColor: '#f59e0b' }]}
                onPress={() => {
                  loadAdminData();
                  setScreen('ADMIN_PANEL');
                }}
              >
                <Text style={[styles.secondaryBtnText, { color: '#fbbf24' }]}>
                  Open Admin Command Center
                </Text>
              </TouchableOpacity>
            )}
          </View>
        )}

        {/* SCREEN 6: 2FA SETUP & RECOVERY CODES */}
        {screen === 'SECURITY_2FA' && user && (
          <View style={styles.card}>
            <Text style={styles.heading}>Two-Factor Authentication (TOTP)</Text>

            {recoveryCodes && (
              <View style={styles.recoveryBox}>
                <Text style={styles.noticeCategory}>
                  SAVE YOUR 8 ONE-TIME RECOVERY CODES:
                </Text>
                {recoveryCodes.map((c) => (
                  <Text key={c} style={styles.monoCode}>
                    {c}
                  </Text>
                ))}
              </View>
            )}

            {!user.twoFactorEnabled ? (
              !qrDataUrl ? (
                <TouchableOpacity
                  style={styles.primaryBtn}
                  onPress={handleStart2FASetup}
                >
                  <Text style={styles.primaryBtnText}>
                    Generate TOTP Secret & QR Code
                  </Text>
                </TouchableOpacity>
              ) : (
                <View>
                  <Image
                    source={{ uri: qrDataUrl }}
                    style={{ width: 180, height: 180, alignSelf: 'center', marginVertical: 10 }}
                  />
                  <Text style={styles.monoCode}>Manual Key: {manualKey}</Text>
                  <TextInput
                    style={styles.input}
                    placeholder="Enter 6-digit code"
                    placeholderTextColor="#64748b"
                    keyboardType="number-pad"
                    value={setupCode}
                    onChangeText={setSetupCode}
                  />
                  <TouchableOpacity
                    style={styles.primaryBtn}
                    onPress={handleEnable2FA}
                  >
                    <Text style={styles.primaryBtnText}>Verify & Enable 2FA</Text>
                  </TouchableOpacity>
                </View>
              )
            ) : (
              <View>
                <Text style={styles.paragraph}>
                  Enter password and 6-digit TOTP or recovery code to disable 2FA:
                </Text>
                <TextInput
                  style={styles.input}
                  placeholder="Current Password"
                  placeholderTextColor="#64748b"
                  secureTextEntry
                  value={disablePass}
                  onChangeText={setDisablePass}
                />
                <TextInput
                  style={styles.input}
                  placeholder="6-digit TOTP or Recovery Code"
                  placeholderTextColor="#64748b"
                  value={disableOtp}
                  onChangeText={setDisableOtp}
                />
                <TouchableOpacity
                  style={[styles.primaryBtn, { backgroundColor: '#e11d48' }]}
                  onPress={handleDisable2FA}
                >
                  <Text style={styles.primaryBtnText}>Disable 2FA</Text>
                </TouchableOpacity>
              </View>
            )}

            <TouchableOpacity
              style={styles.secondaryBtn}
              onPress={() => setScreen('DASHBOARD')}
            >
              <Text style={styles.secondaryBtnText}>Back to Dashboard</Text>
            </TouchableOpacity>
          </View>
        )}

        {/* SCREEN 7: ADMIN MOBILE COMMAND CENTER */}
        {screen === 'ADMIN_PANEL' && user?.role === 'ADMIN' && (
          <View style={styles.card}>
            <Text style={styles.heading}>NKETIAH Admin Mobile Control</Text>
            <TouchableOpacity
              style={styles.primaryBtn}
              onPress={triggerMobileBackup}
            >
              <Text style={styles.primaryBtnText}>
                Trigger Encrypted Firestore Backup
              </Text>
            </TouchableOpacity>

            <Text style={[styles.heading, { marginTop: 16, fontSize: 15 }]}>
              Registered Users ({adminUsers.length})
            </Text>
            {adminUsers.map((u) => (
              <View key={u.id} style={styles.noticeItem}>
                <Text style={styles.noticeTitle}>
                  @{u.username} [{u.role}] - {u.status}
                </Text>
                <Text style={styles.paragraph}>
                  {u.fullName} ({u.studentOrStaffId})
                </Text>
              </View>
            ))}

            <Text style={[styles.heading, { marginTop: 16, fontSize: 15 }]}>
              Encrypted Backups ({adminBackups.length})
            </Text>
            {adminBackups.slice(0, 5).map((b) => (
              <View key={b.id} style={styles.noticeItem}>
                <Text style={styles.noticeCategory}>{b.filename}</Text>
                <Text style={styles.paragraph}>
                  SHA-256: {String(b.checksumSha256).slice(0, 24)}...
                </Text>
              </View>
            ))}

            <TouchableOpacity
              style={styles.secondaryBtn}
              onPress={() => setScreen('DASHBOARD')}
            >
              <Text style={styles.secondaryBtnText}>Back to Dashboard</Text>
            </TouchableOpacity>
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#020617',
  },
  header: {
    paddingHorizontal: 18,
    paddingVertical: 14,
    backgroundColor: '#0f172a',
    borderBottomWidth: 1,
    borderBottomColor: '#1e293b',
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  schoolTitle: {
    color: '#ffffff',
    fontSize: 17,
    fontWeight: '800',
  },
  subtitle: {
    color: '#34d399',
    fontSize: 11,
    marginTop: 2,
  },
  logoutBtn: {
    backgroundColor: '#4c0519',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 8,
  },
  logoutText: {
    color: '#fda4af',
    fontSize: 12,
    fontWeight: '700',
  },
  scrollBody: {
    padding: 16,
  },
  card: {
    backgroundColor: '#0f172a',
    borderRadius: 16,
    padding: 18,
    borderWidth: 1,
    borderColor: '#1e293b',
  },
  heading: {
    color: '#ffffff',
    fontSize: 18,
    fontWeight: '700',
    marginBottom: 8,
  },
  paragraph: {
    color: '#94a3b8',
    fontSize: 13,
    lineHeight: 19,
    marginBottom: 12,
  },
  badge: {
    color: '#34d399',
    fontSize: 12,
    fontWeight: '700',
    marginBottom: 4,
  },
  input: {
    backgroundColor: '#020617',
    borderWidth: 1,
    borderColor: '#1e293b',
    borderRadius: 10,
    color: '#ffffff',
    paddingHorizontal: 14,
    paddingVertical: 11,
    marginBottom: 10,
    fontSize: 14,
  },
  primaryBtn: {
    backgroundColor: '#059669',
    borderRadius: 10,
    paddingVertical: 12,
    alignItems: 'center',
    marginTop: 6,
  },
  primaryBtnText: {
    color: '#ffffff',
    fontWeight: '700',
    fontSize: 14,
  },
  secondaryBtn: {
    backgroundColor: '#1e293b',
    borderRadius: 10,
    paddingVertical: 11,
    alignItems: 'center',
    marginTop: 8,
    borderWidth: 1,
    borderColor: '#334155',
  },
  secondaryBtnText: {
    color: '#e2e8f0',
    fontWeight: '600',
    fontSize: 13,
  },
  banner: {
    padding: 12,
    borderRadius: 10,
    marginBottom: 12,
  },
  bannerOk: {
    backgroundColor: '#064e3b',
  },
  bannerErr: {
    backgroundColor: '#4c0519',
  },
  bannerText: {
    color: '#ffffff',
    fontSize: 13,
    fontWeight: '600',
  },
  noticeItem: {
    backgroundColor: '#020617',
    padding: 12,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: '#1e293b',
    marginTop: 8,
  },
  noticeCategory: {
    color: '#34d399',
    fontSize: 11,
    fontWeight: '700',
  },
  noticeTitle: {
    color: '#ffffff',
    fontSize: 14,
    fontWeight: '700',
    marginVertical: 4,
  },
  recoveryBox: {
    backgroundColor: '#020617',
    padding: 12,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: '#f59e0b',
    marginVertical: 10,
  },
  monoCode: {
    color: '#fde68a',
    fontFamily: 'monospace',
    fontSize: 13,
    marginTop: 4,
  },
});

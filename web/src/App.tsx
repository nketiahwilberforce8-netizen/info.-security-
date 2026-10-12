import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  Lock,
  KeyRound,
  Database,
  Users,
  FileWarning,
  GraduationCap,
  LogOut,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  PlusCircle,
  Trash2,
  QrCode,
  Copy,
  Eye,
  EyeOff,
  Server,
  Smartphone,
  BookOpen,
} from 'lucide-react';
import {
  apiRequest,
  AuditLogEntry,
  BackupEntry,
  SafeUser,
  SchoolNotice,
  setAccessToken,
  trySilentRefresh,
} from './api/client';

type ActiveTab =
  | 'PORTAL_HOME'
  | 'LOGIN'
  | 'REGISTER'
  | 'USER_DASHBOARD'
  | 'SECURITY_2FA'
  | 'ADMIN_USERS'
  | 'ADMIN_NOTICES'
  | 'ADMIN_AUDIT_LOGS'
  | 'ADMIN_BACKUPS';

export function App() {
  const [currentUser, setCurrentUser] = useState<SafeUser | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>('PORTAL_HOME');
  const [loadingInit, setLoadingInit] = useState(true);

  // Global feedback banner
  const [banner, setBanner] = useState<{
    type: 'success' | 'error' | 'info';
    text: string;
  } | null>(null);

  // School Overview & Notices
  const [notices, setNotices] = useState<SchoolNotice[]>([]);
  const [remainingRecoveryCodes, setRemainingRecoveryCodes] = useState<number>(0);

  // Login & 2FA Verification State
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showLoginPass, setShowLoginPass] = useState(false);
  const [preAuthToken, setPreAuthToken] = useState<string | null>(null);
  const [twoFactorCodeInput, setTwoFactorCodeInput] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  // Registration State
  const [regUsername, setRegUsername] = useState('');
  const [regFullName, setRegFullName] = useState('');
  const [regDepartment, setRegDepartment] = useState('Information Technology');
  const [regPassword, setRegPassword] = useState('');
  const [regConfirmPassword, setRegConfirmPassword] = useState('');

  // 2FA Setup & Disable State
  const [qrSetupData, setQrSetupData] = useState<{
    qrCodeDataUrl: string;
    manualEntryKey: string;
    currentTotpCode?: string;
  } | null>(null);
  const [setupVerifyCode, setSetupVerifyCode] = useState('');
  const [twoFactorBusy, setTwoFactorBusy] = useState(false);
  const [inline2FAMessage, setInline2FAMessage] = useState<{
    type: 'success' | 'error' | 'info';
    text: string;
  } | null>(null);
  const [generatedRecoveryCodes, setGeneratedRecoveryCodes] = useState<string[] | null>(
    null
  );
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');

  // Change Password State
  const [currentPassInput, setCurrentPassInput] = useState('');
  const [newPassInput, setNewPassInput] = useState('');
  const [confirmNewPassInput, setConfirmNewPassInput] = useState('');

  // Admin State
  const [adminUsers, setAdminUsers] = useState<SafeUser[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [backups, setBackups] = useState<BackupEntry[]>([]);
  const [adminBusy, setAdminBusy] = useState(false);

  // New School Notice Form
  const [noticeTitle, setNoticeTitle] = useState('');
  const [noticeCategory, setNoticeCategory] = useState<SchoolNotice['category']>('ACADEMIC');
  const [noticeVisibility, setNoticeVisibility] =
    useState<SchoolNotice['visibility']>('PUBLIC');
  const [noticeContent, setNoticeContent] = useState('');

  const showMessage = (type: 'success' | 'error' | 'info', text: string) => {
    setBanner({ type, text });
    setInline2FAMessage({ type, text });
  };

  const fetchSchoolOverview = async () => {
    try {
      const res = await apiRequest('/school/overview');
      setNotices(res.data.notices || []);
    } catch {
      // Ignore public load error
    }
  };

  const fetchMyProfile = async () => {
    try {
      const res = await apiRequest('/users/me');
      setCurrentUser(res.data.user);
      setRemainingRecoveryCodes(res.data.securityProfile?.remainingRecoveryCodes ?? 0);
    } catch {
      // Ignore
    }
  };

  useEffect(() => {
    (async () => {
      const restoredUser = await trySilentRefresh();
      if (restoredUser) {
        setCurrentUser(restoredUser);
        setActiveTab('USER_DASHBOARD');
        await fetchMyProfile();
      }
      await fetchSchoolOverview();
      setLoadingInit(false);
    })();
  }, []);

  useEffect(() => {
    fetchSchoolOverview();
    if (currentUser?.role === 'ADMIN') {
      if (activeTab === 'ADMIN_USERS') loadAdminUsers();
      if (activeTab === 'ADMIN_AUDIT_LOGS') loadAuditLogs();
      if (activeTab === 'ADMIN_BACKUPS') loadBackups();
    }
  }, [activeTab, currentUser]);

  // ==========================================================================
  // AUTHENTICATION HANDLERS
  // ==========================================================================
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBanner(null);
    setAuthLoading(true);
    try {
      const res = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          username: loginUsername,
          password: loginPassword,
        }),
      });

      if (res.requiresTwoFactor) {
        setPreAuthToken(res.data.preAuthToken);
        setTwoFactorCodeInput('');
        showMessage(
          'info',
          'Password verified! Enter your 6-digit Authenticator TOTP code or a Recovery Code.'
        );
      } else {
        setAccessToken(res.data.accessToken);
        setCurrentUser(res.data.user);
        setLoginPassword('');
        setActiveTab('USER_DASHBOARD');
        showMessage('success', `Welcome back, ${res.data.user.fullName}!`);
        await fetchMyProfile();
      }
    } catch (err) {
      showMessage('error', (err as Error).message);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleVerify2FASubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!preAuthToken) return;
    setBanner(null);
    setAuthLoading(true);
    try {
      const res = await apiRequest('/auth/verify-2fa', {
        method: 'POST',
        body: JSON.stringify({
          preAuthToken,
          code: twoFactorCodeInput,
        }),
      });

      setAccessToken(res.data.accessToken);
      setCurrentUser(res.data.user);
      setPreAuthToken(null);
      setTwoFactorCodeInput('');
      setLoginPassword('');
      setActiveTab('USER_DASHBOARD');
      showMessage('success', res.message);
      await fetchMyProfile();
    } catch (err) {
      showMessage('error', (err as Error).message);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBanner(null);
    setAuthLoading(true);
    try {
      const res = await apiRequest('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          username: regUsername,
          fullName: regFullName,
          department: regDepartment,
          password: regPassword,
          confirmPassword: regConfirmPassword,
        }),
      });

      setAccessToken(res.data.accessToken);
      setCurrentUser(res.data.user);
      setRegPassword('');
      setRegConfirmPassword('');
      setActiveTab('USER_DASHBOARD');
      showMessage('success', res.message);
      await fetchMyProfile();
    } catch (err) {
      showMessage('error', (err as Error).message);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await apiRequest('/auth/logout', { method: 'POST' });
    } catch {
      // Ignore logout error
    }
    setAccessToken(null);
    setCurrentUser(null);
    setPreAuthToken(null);
    setQrSetupData(null);
    setGeneratedRecoveryCodes(null);
    setActiveTab('PORTAL_HOME');
    showMessage('info', 'You have been securely logged out of NKETIAH.');
  };

  // ==========================================================================
  // 2FA & SECURITY SETTINGS HANDLERS
  // ==========================================================================
  const handleStart2FASetup = async () => {
    setBanner(null);
    setInline2FAMessage(null);
    setTwoFactorBusy(true);
    try {
      const res = await apiRequest('/auth/2fa/setup', { method: 'POST' });
      setQrSetupData({
        qrCodeDataUrl: res.data.qrCodeDataUrl,
        manualEntryKey: res.data.manualEntryKey,
        currentTotpCode: res.data.currentTotpCode,
      });
      if (res.data.currentTotpCode) {
        setSetupVerifyCode(res.data.currentTotpCode);
      }
      setGeneratedRecoveryCodes(null);
      showMessage(
        'info',
        'QR code generated! Scan with Google/Microsoft Authenticator or click Verify & Activate 2FA.'
      );
    } catch (err) {
      showMessage('error', (err as Error).message);
    } finally {
      setTwoFactorBusy(false);
    }
  };

  const handleAutoFillServerCode = async (target: 'SETUP' | 'LOGIN' | 'DISABLE') => {
    setInline2FAMessage(null);
    try {
      const res = await apiRequest('/auth/2fa/live-code', {
        method: 'POST',
        body: JSON.stringify({ preAuthToken }),
      });
      const liveCode = res.data.currentTotpCode;
      if (target === 'SETUP') {
        setSetupVerifyCode(liveCode);
        setQrSetupData((prev) => (prev ? { ...prev, currentTotpCode: liveCode } : prev));
      } else if (target === 'LOGIN') {
        setTwoFactorCodeInput(liveCode);
      } else {
        setDisableCode(liveCode);
      }
      showMessage(
        'info',
        `Synced live 6-digit TOTP code (${liveCode}) from server clock (${res.data.secondsRemaining}s remaining in window).`
      );
    } catch (err) {
      showMessage('error', (err as Error).message);
    }
  };

  const handleEnable2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    setBanner(null);
    setInline2FAMessage(null);
    setTwoFactorBusy(true);
    try {
      const res = await apiRequest('/auth/2fa/enable', {
        method: 'POST',
        body: JSON.stringify({ code: setupVerifyCode.trim() }),
      });
      setCurrentUser(res.data.user);
      setGeneratedRecoveryCodes(res.data.recoveryCodes);
      setQrSetupData(null);
      setSetupVerifyCode('');
      await fetchMyProfile();
      showMessage('success', res.message);
    } catch (err) {
      showMessage('error', (err as Error).message);
    } finally {
      setTwoFactorBusy(false);
    }
  };

  const handleDisable2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    setBanner(null);
    setInline2FAMessage(null);
    setTwoFactorBusy(true);
    try {
      const res = await apiRequest('/auth/2fa/disable', {
        method: 'POST',
        body: JSON.stringify({
          password: disablePassword,
          code: disableCode.trim(),
        }),
      });
      setCurrentUser(res.data.user);
      setDisablePassword('');
      setDisableCode('');
      setGeneratedRecoveryCodes(null);
      await fetchMyProfile();
      showMessage('info', res.message);
    } catch (err) {
      showMessage('error', (err as Error).message);
    } finally {
      setTwoFactorBusy(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setBanner(null);
    try {
      const res = await apiRequest('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({
          currentPassword: currentPassInput,
          newPassword: newPassInput,
          confirmNewPassword: confirmNewPassInput,
        }),
      });
      setCurrentPassInput('');
      setNewPassInput('');
      setConfirmNewPassInput('');
      showMessage('success', res.message);
    } catch (err) {
      showMessage('error', (err as Error).message);
    }
  };

  // ==========================================================================
  // ADMIN HANDLERS
  // ==========================================================================
  const loadAdminUsers = async () => {
    try {
      const res = await apiRequest('/admin/users');
      setAdminUsers(res.data.users || []);
    } catch (err) {
      showMessage('error', (err as Error).message);
    }
  };

  const loadAuditLogs = async () => {
    try {
      const res = await apiRequest('/admin/audit-logs');
      setAuditLogs(res.data.auditLogs || []);
    } catch (err) {
      showMessage('error', (err as Error).message);
    }
  };

  const loadBackups = async () => {
    try {
      const res = await apiRequest('/admin/backups');
      setBackups(res.data.backups || []);
    } catch (err) {
      showMessage('error', (err as Error).message);
    }
  };

  const handleToggleUserRole = async (u: SafeUser) => {
    const nextRole = u.role === 'ADMIN' ? 'USER' : 'ADMIN';
    try {
      const res = await apiRequest(`/admin/users/${u.id}/role`, {
        method: 'PATCH',
        body: JSON.stringify({ role: nextRole }),
      });
      showMessage('success', res.message);
      await loadAdminUsers();
    } catch (err) {
      showMessage('error', (err as Error).message);
    }
  };

  const handleToggleUserStatus = async (u: SafeUser) => {
    const nextStatus = u.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE';
    try {
      const res = await apiRequest(`/admin/users/${u.id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status: nextStatus }),
      });
      showMessage('success', res.message);
      await loadAdminUsers();
    } catch (err) {
      showMessage('error', (err as Error).message);
    }
  };

  const handleDeleteUser = async (u: SafeUser) => {
    if (!window.confirm(`Permanently delete NKETIAH account '${u.username}'?`)) return;
    try {
      const res = await apiRequest(`/admin/users/${u.id}`, {
        method: 'DELETE',
      });
      showMessage('info', res.message);
      await loadAdminUsers();
    } catch (err) {
      showMessage('error', (err as Error).message);
    }
  };

  const handleCreateNotice = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiRequest('/school/notices', {
        method: 'POST',
        body: JSON.stringify({
          title: noticeTitle,
          category: noticeCategory,
          visibility: noticeVisibility,
          content: noticeContent,
        }),
      });
      setNoticeTitle('');
      setNoticeContent('');
      showMessage('success', res.message);
      await fetchSchoolOverview();
    } catch (err) {
      showMessage('error', (err as Error).message);
    }
  };

  const handleDeleteNotice = async (id: string) => {
    try {
      await apiRequest(`/school/notices/${id}`, { method: 'DELETE' });
      showMessage('info', 'Notice removed.');
      await fetchSchoolOverview();
    } catch (err) {
      showMessage('error', (err as Error).message);
    }
  };

  const handleTriggerBackup = async () => {
    setAdminBusy(true);
    setBanner(null);
    try {
      const res = await apiRequest('/admin/backups', { method: 'POST' });
      showMessage('success', res.message);
      await loadBackups();
    } catch (err) {
      showMessage('error', (err as Error).message);
    } finally {
      setAdminBusy(false);
    }
  };

  const handleRestoreBackup = async (backupId: string, filename: string) => {
    if (
      !window.confirm(
        `Restore entire NKETIAH Firestore database from encrypted backup '${filename}'?`
      )
    ) {
      return;
    }
    setAdminBusy(true);
    setBanner(null);
    try {
      const res = await apiRequest(`/admin/backups/${backupId}/restore`, {
        method: 'POST',
      });
      showMessage('success', res.message);
      await loadBackups();
      await fetchSchoolOverview();
    } catch (err) {
      showMessage('error', (err as Error).message);
    } finally {
      setAdminBusy(false);
    }
  };

  const activeRole = currentUser ? currentUser.role : 'GUEST';

  if (loadingInit) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center">
        <div className="flex items-center gap-3 text-emerald-400 font-medium">
          <RefreshCw className="w-6 h-6 animate-spin" />
          <span>Initializing NKETIAH Security Portal...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* TOP NAVIGATION HEADER */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
          <div
            onClick={() =>
              setActiveTab(currentUser ? 'USER_DASHBOARD' : 'PORTAL_HOME')
            }
            className="flex items-center gap-3 cursor-pointer"
          >
            <div className="w-10 h-10 rounded-xl bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <GraduationCap className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight text-white">
                  NKETIAH
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold">
                  School Management System
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Argon2id (Salt+Pepper) • TOTP 2FA • AES-256-GCM • Firestore Backups
              </p>
            </div>
          </div>

          {/* NAVIGATION TABS */}
          <nav className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setActiveTab('PORTAL_HOME')}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'PORTAL_HOME'
                  ? 'bg-emerald-600 text-white'
                  : 'text-slate-300 hover:bg-slate-800'
              }`}
            >
              Public Portal
            </button>

            {!currentUser && (
              <>
                <button
                  onClick={() => {
                    setPreAuthToken(null);
                    setActiveTab('LOGIN');
                  }}
                  className={`px-3.5 py-1.5 rounded-lg text-sm font-medium transition ${
                    activeTab === 'LOGIN'
                      ? 'bg-emerald-600 text-white'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  Login
                </button>
                <button
                  onClick={() => setActiveTab('REGISTER')}
                  className={`px-3.5 py-1.5 rounded-lg text-sm font-medium transition ${
                    activeTab === 'REGISTER'
                      ? 'bg-emerald-600 text-white'
                      : 'bg-slate-800 text-emerald-300 hover:bg-slate-700'
                  }`}
                >
                  Register Student/Staff
                </button>
              </>
            )}

            {currentUser && (
              <>
                <button
                  onClick={() => setActiveTab('USER_DASHBOARD')}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                    activeTab === 'USER_DASHBOARD'
                      ? 'bg-emerald-600 text-white'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  Dashboard
                </button>
                <button
                  onClick={() => setActiveTab('SECURITY_2FA')}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                    activeTab === 'SECURITY_2FA'
                      ? 'bg-emerald-600 text-white'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  2FA & Security
                </button>
              </>
            )}

            {currentUser?.role === 'ADMIN' && (
              <>
                <button
                  onClick={() => setActiveTab('ADMIN_USERS')}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                    activeTab === 'ADMIN_USERS'
                      ? 'bg-amber-600 text-white'
                      : 'text-amber-300 hover:bg-slate-800'
                  }`}
                >
                  Admin: Users
                </button>
                <button
                  onClick={() => setActiveTab('ADMIN_NOTICES')}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                    activeTab === 'ADMIN_NOTICES'
                      ? 'bg-amber-600 text-white'
                      : 'text-amber-300 hover:bg-slate-800'
                  }`}
                >
                  Admin: Notices
                </button>
                <button
                  onClick={() => setActiveTab('ADMIN_AUDIT_LOGS')}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                    activeTab === 'ADMIN_AUDIT_LOGS'
                      ? 'bg-amber-600 text-white'
                      : 'text-amber-300 hover:bg-slate-800'
                  }`}
                >
                  Audit Logs
                </button>
                <button
                  onClick={() => setActiveTab('ADMIN_BACKUPS')}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                    activeTab === 'ADMIN_BACKUPS'
                      ? 'bg-amber-600 text-white'
                      : 'text-amber-300 hover:bg-slate-800'
                  }`}
                >
                  Backups & Restore
                </button>
              </>
            )}

            {/* ACTIVE ROLE BADGE & LOGOUT */}
            <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
              <span
                className={`text-xs font-bold px-2.5 py-1 rounded-md border ${
                  activeRole === 'ADMIN'
                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                    : activeRole === 'USER'
                    ? 'bg-sky-500/20 text-sky-300 border-sky-500/40'
                    : 'bg-slate-800 text-slate-300 border-slate-700'
                }`}
              >
                ROLE: {activeRole}
              </span>
              {currentUser && (
                <button
                  onClick={handleLogout}
                  title="Sign out"
                  className="p-1.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/30 hover:bg-rose-500/20 transition"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              )}
            </div>
          </nav>
        </div>
      </header>

      {/* MAIN CONTENT CONTAINER */}
      <main className="max-w-7xl w-full mx-auto px-4 sm:px-6 py-8 flex-1 space-y-6">
        {/* FEEDBACK BANNER */}
        {banner && (
          <div
            className={`p-4 rounded-xl border flex items-center justify-between gap-3 ${
              banner.type === 'success'
                ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-200'
                : banner.type === 'error'
                ? 'bg-rose-950/60 border-rose-500/40 text-rose-200'
                : 'bg-sky-950/60 border-sky-500/40 text-sky-200'
            }`}
          >
            <div className="flex items-center gap-3 text-sm font-medium">
              {banner.type === 'success' ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
              )}
              <span>{banner.text}</span>
            </div>
            <button
              onClick={() => setBanner(null)}
              className="text-xs opacity-75 hover:opacity-100"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* ==================================================================
            VIEW 1: PUBLIC SCHOOL PORTAL (GUEST / USER / ADMIN)
           ================================================================== */}
        {activeTab === 'PORTAL_HOME' && (
          <div className="space-y-8">
            {/* Hero Banner */}
            <div className="rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-emerald-950/60 border border-slate-800 p-6 sm:p-8 shadow-xl">
              <div className="max-w-3xl space-y-4">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs font-semibold">
                  <ShieldCheck className="w-4 h-4" />
                  <span>NKETIAH Academic & Cybersecurity Portal</span>
                </div>
                <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
                  NKETIAH School Management System
                </h1>
                <p className="text-slate-300 text-sm sm:text-base leading-relaxed">
                  A centralized Role-Based Academic & Security Platform serving both Web and
                  Expo Mobile clients. Engineered with{' '}
                  <strong className="text-white">
                    Username-Only Authentication
                  </strong>
                  , <strong className="text-white">Argon2id (Salt + Server Pepper)</strong>,{' '}
                  <strong className="text-white">TOTP 2FA</strong>,{' '}
                  <strong className="text-white">AES-256-GCM Encryption</strong>, and{' '}
                  <strong className="text-white">
                    Automated Firestore Cloud Backups
                  </strong>
                  .
                </p>
                {!currentUser && (
                  <div className="flex flex-wrap gap-3 pt-2">
                    <button
                      onClick={() => setActiveTab('LOGIN')}
                      className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-sm transition cursor-pointer"
                    >
                      Sign In with Username
                    </button>
                    <button
                      onClick={() => setActiveTab('REGISTER')}
                      className="px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 font-semibold text-sm transition cursor-pointer"
                    >
                      Create Student / Staff Account
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Security Architecture Pillar Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                <div className="w-9 h-9 rounded-lg bg-emerald-500/15 text-emerald-400 flex items-center justify-center">
                  <Lock className="w-5 h-5" />
                </div>
                <h3 className="font-bold text-white text-sm">
                  Argon2id + Salt + Pepper
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Passwords are never stored in plaintext or encrypted. Every password gets a
                  128-bit unique salt + HMAC-SHA256 Server Pepper outside Firestore before
                  64 MiB Argon2id hashing.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                <div className="w-9 h-9 rounded-lg bg-sky-500/15 text-sky-400 flex items-center justify-center">
                  <KeyRound className="w-5 h-5" />
                </div>
                <h3 className="font-bold text-white text-sm">
                  AES-256-GCM + TOTP 2FA
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  RFC 6238 TOTP secrets are encrypted at rest using AES-256-GCM with a unique
                  96-bit IV and 128-bit Authentication Tag, paired with 8 hashed recovery codes.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                <div className="w-9 h-9 rounded-lg bg-amber-500/15 text-amber-400 flex items-center justify-center">
                  <Users className="w-5 h-5" />
                </div>
                <h3 className="font-bold text-white text-sm">
                  Strict RBAC (GUEST / USER / ADMIN)
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Role-Based Authorization is enforced on the Node.js Backend API. Unauthorized
                  requests are blocked with HTTP 403 and recorded in Firestore Audit Logs.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                <div className="w-9 h-9 rounded-lg bg-purple-500/15 text-purple-400 flex items-center justify-center">
                  <Database className="w-5 h-5" />
                </div>
                <h3 className="font-bold text-white text-sm">
                  Automated Firestore Backups
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Scheduled Cron snapshots export all Firestore collections, compute SHA-256
                  checksums, encrypt with AES-256-GCM, and support 1-click database recovery.
                </p>
              </div>
            </div>

            {/* NKETIAH School Noticeboard */}
            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <BookOpen className="w-5 h-5 text-emerald-400" />
                  <h2 className="text-lg font-bold text-white">
                    NKETIAH Official Noticeboard (Visible to Role: {activeRole})
                  </h2>
                </div>
                <span className="text-xs text-slate-400">
                  Showing {notices.length} notice(s)
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {notices.map((n) => (
                  <div
                    key={n.id}
                    className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col justify-between gap-3"
                  >
                    <div className="space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                          {n.category}
                        </span>
                        <span
                          className={`text-[11px] font-mono px-2 py-0.5 rounded ${
                            n.visibility === 'ADMIN_ONLY'
                              ? 'bg-amber-500/20 text-amber-300'
                              : n.visibility === 'AUTHENTICATED_ONLY'
                              ? 'bg-sky-500/20 text-sky-300'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {n.visibility}
                        </span>
                      </div>
                      <h3 className="font-bold text-white text-base">{n.title}</h3>
                      <p className="text-xs text-slate-300 leading-relaxed">{n.content}</p>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-slate-500 pt-2 border-t border-slate-900">
                      <span>Posted by @{n.authorUsername}</span>
                      <span>{new Date(n.createdAt).toLocaleDateString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================
            VIEW 2: USERNAME + PASSWORD LOGIN & 2FA VERIFICATION
           ================================================================== */}
        {activeTab === 'LOGIN' && !currentUser && (
          <div className="max-w-md mx-auto rounded-2xl bg-slate-900 border border-slate-800 p-6 sm:p-8 space-y-6 shadow-xl">
            {!preAuthToken ? (
              <>
                <div className="space-y-1 text-center">
                  <div className="w-12 h-12 rounded-2xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 flex items-center justify-center mx-auto mb-2">
                    <Lock className="w-6 h-6" />
                  </div>
                  <h2 className="text-xl font-bold text-white">
                    NKETIAH Portal Sign In
                  </h2>
                  <p className="text-xs text-slate-400">
                    Authenticate using ONLY your Username and Password (no email required).
                  </p>
                </div>

                {/* Quick Demo Credential Fillers for Lecturer Presentation */}
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Quick Lecturer Demo Credentials:
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setLoginUsername('nketiah_admin');
                        setLoginPassword('Admin@Nketiah2026!');
                      }}
                      className="px-2.5 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 text-xs font-medium transition cursor-pointer"
                    >
                      Fill Admin (ADMIN)
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setLoginUsername('kwame_student');
                        setLoginPassword('Student@Nketiah2026!');
                      }}
                      className="px-2.5 py-1.5 rounded-lg bg-sky-500/15 hover:bg-sky-500/25 border border-sky-500/30 text-sky-300 text-xs font-medium transition cursor-pointer"
                    >
                      Fill Student (USER)
                    </button>
                  </div>
                </div>

                <form onSubmit={handleLoginSubmit} className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Username
                    </label>
                    <input
                      type="text"
                      required
                      value={loginUsername}
                      onChange={(e) => setLoginUsername(e.target.value)}
                      placeholder="e.g., nketiah_admin or kwame_student"
                      className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-emerald-500"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-300 mb-1">
                      Password
                    </label>
                    <div className="relative">
                      <input
                        type={showLoginPass ? 'text' : 'password'}
                        required
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        placeholder="Enter your password"
                        className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-emerald-500 pr-10"
                      />
                      <button
                        type="button"
                        onClick={() => setShowLoginPass(!showLoginPass)}
                        className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-200"
                      >
                        {showLoginPass ? (
                          <EyeOff className="w-4 h-4" />
                        ) : (
                          <Eye className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                  </div>

                  {inline2FAMessage && (
                    <div
                      className={`p-3 rounded-xl text-xs font-medium border ${
                        inline2FAMessage.type === 'error'
                          ? 'bg-rose-950/70 border-rose-500/40 text-rose-200'
                          : inline2FAMessage.type === 'success'
                          ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-200'
                          : 'bg-sky-950/70 border-sky-500/40 text-sky-200'
                      }`}
                    >
                      {inline2FAMessage.text}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={authLoading}
                    className="w-full py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-sm transition cursor-pointer"
                  >
                    {authLoading ? 'Verifying Argon2id Hash...' : 'Sign In'}
                  </button>
                </form>
              </>
            ) : (
              /* STEP 2: TOTP 2FA OR RECOVERY CODE VERIFICATION */
              <form onSubmit={handleVerify2FASubmit} className="space-y-4">
                <div className="space-y-1 text-center">
                  <div className="w-12 h-12 rounded-2xl bg-sky-500/15 border border-sky-500/30 text-sky-400 flex items-center justify-center mx-auto mb-2">
                    <Smartphone className="w-6 h-6" />
                  </div>
                  <h2 className="text-xl font-bold text-white">
                    Two-Factor Authentication (2FA)
                  </h2>
                  <p className="text-xs text-slate-400">
                    Enter the 6-digit code from Google/Microsoft Authenticator or a one-time
                    recovery code (`NKET-XXXX-XXXX`).
                  </p>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="block text-xs font-semibold text-slate-300">
                      6-Digit TOTP Code or Recovery Code
                    </label>
                    <button
                      type="button"
                      onClick={() => handleAutoFillServerCode('LOGIN')}
                      className="text-[11px] font-semibold text-sky-400 hover:text-sky-300 underline cursor-pointer"
                    >
                      Auto-Fill Live Server TOTP Code
                    </button>
                  </div>
                  <input
                    type="text"
                    required
                    value={twoFactorCodeInput}
                    onChange={(e) => setTwoFactorCodeInput(e.target.value)}
                    placeholder="123456 or NKET-XXXX-XXXX"
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-center font-mono tracking-widest text-base focus:outline-none focus:border-sky-500"
                  />
                </div>

                {inline2FAMessage && (
                  <div
                    className={`p-3 rounded-xl text-xs font-medium border ${
                      inline2FAMessage.type === 'error'
                        ? 'bg-rose-950/70 border-rose-500/40 text-rose-200'
                        : inline2FAMessage.type === 'success'
                        ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-200'
                        : 'bg-sky-950/70 border-sky-500/40 text-sky-200'
                    }`}
                  >
                    {inline2FAMessage.text}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={authLoading}
                  className="w-full py-2.5 rounded-xl bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold text-sm transition cursor-pointer"
                >
                  {authLoading ? 'Decrypting Secret & Verifying...' : 'Verify 2FA Code'}
                </button>

                <button
                  type="button"
                  onClick={() => setPreAuthToken(null)}
                  className="w-full py-2 rounded-xl bg-slate-800 text-slate-300 text-xs font-medium hover:bg-slate-700"
                >
                  Back to Username / Password
                </button>
              </form>
            )}
          </div>
        )}

        {/* ==================================================================
            VIEW 3: STUDENT / STAFF REGISTRATION (NO EMAIL REQUIRED)
           ================================================================== */}
        {activeTab === 'REGISTER' && !currentUser && (
          <div className="max-w-lg mx-auto rounded-2xl bg-slate-900 border border-slate-800 p-6 sm:p-8 space-y-6 shadow-xl">
            <div className="space-y-1 text-center">
              <h2 className="text-xl font-bold text-white">
                Register NKETIAH Portal Account
              </h2>
              <p className="text-xs text-slate-400">
                Username-only identification. Your password will be protected with a unique
                128-bit Salt + Server Pepper + Argon2id.
              </p>
            </div>

            <form onSubmit={handleRegisterSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Unique Username *
                </label>
                <input
                  type="text"
                  required
                  value={regUsername}
                  onChange={(e) => setRegUsername(e.target.value)}
                  placeholder="e.g., kofi_mensah"
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Full Name
                  </label>
                  <input
                    type="text"
                    value={regFullName}
                    onChange={(e) => setRegFullName(e.target.value)}
                    placeholder="e.g., Kofi Mensah"
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    NKETIAH Department
                  </label>
                  <select
                    value={regDepartment}
                    onChange={(e) => setRegDepartment(e.target.value)}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-emerald-500"
                  >
                    <option value="Information Technology">Information Technology</option>
                    <option value="Computer Science">Computer Science</option>
                    <option value="Cybersecurity & Forensics">
                      Cybersecurity & Forensics
                    </option>
                    <option value="Software Engineering">Software Engineering</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Password *
                  </label>
                  <input
                    type="password"
                    required
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    placeholder="Min 8 chars, A-Z, a-z, 0-9, symbol"
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-emerald-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Confirm Password *
                  </label>
                  <input
                    type="password"
                    required
                    value={regConfirmPassword}
                    onChange={(e) => setRegConfirmPassword(e.target.value)}
                    placeholder="Repeat password"
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              {inline2FAMessage && (
                <div
                  className={`p-3 rounded-xl text-xs font-medium border ${
                    inline2FAMessage.type === 'error'
                      ? 'bg-rose-950/70 border-rose-500/40 text-rose-200'
                      : inline2FAMessage.type === 'success'
                      ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-200'
                      : 'bg-sky-950/70 border-sky-500/40 text-sky-200'
                  }`}
                >
                  {inline2FAMessage.text}
                </div>
              )}

              <button
                type="submit"
                disabled={authLoading}
                className="w-full py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-sm transition cursor-pointer"
              >
                {authLoading ? 'Hashing with Argon2id & Creating Account...' : 'Create Account'}
              </button>
            </form>
          </div>
        )}

        {/* ==================================================================
            VIEW 4: AUTHENTICATED USER DASHBOARD
           ================================================================== */}
        {activeTab === 'USER_DASHBOARD' && currentUser && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Student / Staff Identity Card */}
              <div className="lg:col-span-2 rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <span className="text-xs font-mono text-emerald-400">
                      {currentUser.studentOrStaffId}
                    </span>
                    <h2 className="text-2xl font-bold text-white mt-0.5">
                      {currentUser.fullName}
                    </h2>
                    <p className="text-sm text-slate-400">
                      @{currentUser.username} • {currentUser.department}
                    </p>
                  </div>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-bold border ${
                      currentUser.role === 'ADMIN'
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                        : 'bg-sky-500/20 text-sky-300 border-sky-500/40'
                    }`}
                  >
                    {currentUser.role}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
                  <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                    <p className="text-[11px] text-slate-400">Password Protection</p>
                    <p className="text-xs font-semibold text-emerald-400 mt-1">
                      Argon2id + Salt + Pepper
                    </p>
                  </div>
                  <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                    <p className="text-[11px] text-slate-400">Two-Factor Auth (2FA)</p>
                    <p
                      className={`text-xs font-semibold mt-1 ${
                        currentUser.twoFactorEnabled ? 'text-emerald-400' : 'text-amber-400'
                      }`}
                    >
                      {currentUser.twoFactorEnabled
                        ? `Enabled (${remainingRecoveryCodes} recovery codes left)`
                        : 'Not Enabled (Click 2FA & Security)'}
                    </p>
                  </div>
                  <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                    <p className="text-[11px] text-slate-400">TOTP Secret Storage</p>
                    <p className="text-xs font-semibold text-sky-400 mt-1">
                      AES-256-GCM Encrypted
                    </p>
                  </div>
                </div>
              </div>

              {/* Quick Actions */}
              <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 flex flex-col justify-between space-y-4">
                <div className="space-y-2">
                  <h3 className="font-bold text-white text-base">
                    Account Security Posture
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Manage your TOTP Authenticator app, generate emergency recovery codes, or
                    rotate your Argon2id password hash.
                  </p>
                </div>
                <div className="space-y-2">
                  <button
                    onClick={() => setActiveTab('SECURITY_2FA')}
                    className="w-full py-2.5 px-4 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition cursor-pointer"
                  >
                    Manage 2FA & Cryptographic Settings
                  </button>
                  {currentUser.role === 'ADMIN' && (
                    <button
                      onClick={() => setActiveTab('ADMIN_BACKUPS')}
                      className="w-full py-2.5 px-4 rounded-xl bg-amber-600/20 hover:bg-amber-600/30 border border-amber-500/40 text-amber-300 text-xs font-semibold transition cursor-pointer"
                    >
                      Open Admin Backups & Recovery
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Authenticated School Notices */}
            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
              <h3 className="font-bold text-white text-lg">
                NKETIAH Academic & Security Bulletins
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {notices.map((n) => (
                  <div
                    key={n.id}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-emerald-400">
                        {n.category}
                      </span>
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {n.visibility}
                      </span>
                    </div>
                    <h4 className="font-bold text-white text-sm">{n.title}</h4>
                    <p className="text-xs text-slate-300 leading-relaxed">{n.content}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================
            VIEW 5: 2FA SETUP, RECOVERY CODES & PASSWORD SECURITY
           ================================================================== */}
        {activeTab === 'SECURITY_2FA' && currentUser && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* TOTP 2FA Card */}
            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <QrCode className="w-5 h-5 text-emerald-400" />
                  <h3 className="font-bold text-white text-lg">
                    Two-Factor Authentication (TOTP)
                  </h3>
                </div>
                <span
                  className={`text-xs font-bold px-2.5 py-1 rounded-full ${
                    currentUser.twoFactorEnabled
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {currentUser.twoFactorEnabled ? 'ACTIVE' : 'INACTIVE'}
                </span>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">
                When enabled, your TOTP secret is encrypted using{' '}
                <strong className="text-slate-200">
                  AES-256-GCM (96-bit IV + 128-bit Auth Tag)
                </strong>{' '}
                before being stored in Firestore.
              </p>

              {/* One-Time Recovery Codes Display Box */}
              {generatedRecoveryCodes && (
                <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-500/40 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-amber-300">
                      SAVE YOUR 8 ONE-TIME RECOVERY CODES NOW!
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(generatedRecoveryCodes.join('\n'));
                        showMessage('info', 'Recovery codes copied to clipboard!');
                      }}
                      className="inline-flex items-center gap-1 text-xs text-amber-200 hover:text-white"
                    >
                      <Copy className="w-3.5 h-3.5" /> Copy All
                    </button>
                  </div>
                  <p className="text-[11px] text-amber-200/80">
                    These codes are stored only as HMAC-SHA256 hashes in Firestore and will
                    never be shown again. Each code can be used once if you lose your phone.
                  </p>
                  <div className="grid grid-cols-2 gap-2 font-mono text-xs bg-slate-950 p-3 rounded-lg border border-amber-500/20 text-emerald-300">
                    {generatedRecoveryCodes.map((code) => (
                      <div key={code}>{code}</div>
                    ))}
                  </div>
                </div>
              )}

              {!currentUser.twoFactorEnabled ? (
                !qrSetupData ? (
                  <button
                    onClick={handleStart2FASetup}
                    disabled={twoFactorBusy}
                    className="w-full py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-sm transition cursor-pointer"
                  >
                    {twoFactorBusy
                      ? 'Generating AES-256-GCM Encrypted Secret...'
                      : 'Generate TOTP Secret & QR Code'}
                  </button>
                ) : (
                  <form onSubmit={handleEnable2FA} className="space-y-4">
                    <div className="flex flex-col items-center p-4 rounded-xl bg-white text-slate-900 space-y-2">
                      <img
                        src={qrSetupData.qrCodeDataUrl}
                        alt="TOTP QR Code"
                        className="w-48 h-48"
                      />
                      <p className="text-xs font-mono font-bold tracking-wider break-all text-center">
                        Manual Key: {qrSetupData.manualEntryKey}
                      </p>
                    </div>

                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="block text-xs font-semibold text-slate-300">
                          Enter 6-Digit Code from Authenticator App to Confirm
                        </label>
                        <button
                          type="button"
                          onClick={() => handleAutoFillServerCode('SETUP')}
                          className="text-[11px] font-semibold text-emerald-400 hover:text-emerald-300 underline cursor-pointer"
                        >
                          Auto-Fill Server TOTP Code
                        </button>
                      </div>
                      <input
                        type="text"
                        required
                        value={setupVerifyCode}
                        onChange={(e) => setSetupVerifyCode(e.target.value)}
                        placeholder="123456"
                        className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-center font-mono text-base focus:outline-none focus:border-emerald-500"
                      />
                    </div>

                    {inline2FAMessage && (
                      <div
                        className={`p-3 rounded-xl text-xs font-medium border ${
                          inline2FAMessage.type === 'error'
                            ? 'bg-rose-950/70 border-rose-500/40 text-rose-200'
                            : inline2FAMessage.type === 'success'
                            ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-200'
                            : 'bg-sky-950/70 border-sky-500/40 text-sky-200'
                        }`}
                      >
                        {inline2FAMessage.text}
                      </div>
                    )}

                    <button
                      type="submit"
                      disabled={twoFactorBusy}
                      className="w-full py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-sm transition cursor-pointer"
                    >
                      {twoFactorBusy
                        ? 'Verifying 6-Digit Code & Activating 2FA...'
                        : 'Verify & Activate 2FA'}
                    </button>
                  </form>
                )
              ) : (
                <form
                  onSubmit={handleDisable2FA}
                  className="space-y-3 pt-3 border-t border-slate-800"
                >
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold text-rose-400 uppercase tracking-wider">
                      Disable Two-Factor Authentication
                    </h4>
                    <button
                      type="button"
                      onClick={() => handleAutoFillServerCode('DISABLE')}
                      className="text-[11px] font-semibold text-emerald-400 hover:text-emerald-300 underline cursor-pointer"
                    >
                      Auto-Fill Server TOTP Code
                    </button>
                  </div>
                  <input
                    type="password"
                    required
                    value={disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    placeholder="Confirm your current password"
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm"
                  />
                  <input
                    type="text"
                    required
                    value={disableCode}
                    onChange={(e) => setDisableCode(e.target.value)}
                    placeholder="6-digit TOTP code or Recovery Code"
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm font-mono"
                  />

                  {inline2FAMessage && (
                    <div
                      className={`p-3 rounded-xl text-xs font-medium border ${
                        inline2FAMessage.type === 'error'
                          ? 'bg-rose-950/70 border-rose-500/40 text-rose-200'
                          : inline2FAMessage.type === 'success'
                          ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-200'
                          : 'bg-sky-950/70 border-sky-500/40 text-sky-200'
                      }`}
                    >
                      {inline2FAMessage.text}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={twoFactorBusy}
                    className="w-full py-2 rounded-xl bg-rose-600/20 hover:bg-rose-600/30 disabled:opacity-50 border border-rose-500/40 text-rose-300 text-xs font-semibold transition cursor-pointer"
                  >
                    {twoFactorBusy ? 'Disabling 2FA...' : 'Disable 2FA'}
                  </button>
                </form>
              )}
            </div>

            {/* Password Change Card */}
            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
              <div className="flex items-center gap-2.5">
                <KeyRound className="w-5 h-5 text-sky-400" />
                <h3 className="font-bold text-white text-lg">
                  Rotate Password (Argon2id + Salt + Pepper)
                </h3>
              </div>
              <p className="text-xs text-slate-400">
                Changing your password generates a brand-new 128-bit cryptographic salt,
                applies the server-side HMAC-SHA256 pepper, and revokes older refresh sessions.
              </p>

              <form onSubmit={handleChangePassword} className="space-y-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Current Password
                  </label>
                  <input
                    type="password"
                    required
                    value={currentPassInput}
                    onChange={(e) => setCurrentPassInput(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    New Password
                  </label>
                  <input
                    type="password"
                    required
                    value={newPassInput}
                    onChange={(e) => setNewPassInput(e.target.value)}
                    placeholder="Min 8 chars, uppercase, lowercase, number, symbol"
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Confirm New Password
                  </label>
                  <input
                    type="password"
                    required
                    value={confirmNewPassInput}
                    onChange={(e) => setConfirmNewPassInput(e.target.value)}
                    className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm"
                  />
                </div>
                <button
                  type="submit"
                  className="w-full py-2.5 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-semibold text-sm transition cursor-pointer"
                >
                  Update Password
                </button>
              </form>
            </div>
          </div>
        )}

        {/* ==================================================================
            VIEW 6: ADMIN USER & ROLE MANAGEMENT
           ================================================================== */}
        {activeTab === 'ADMIN_USERS' && currentUser?.role === 'ADMIN' && (
          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-white">
                  NKETIAH User & Role-Based Authorization Management
                </h2>
                <p className="text-xs text-slate-400">
                  Promote/demote roles (`USER` ↔ `ADMIN`), enable/disable accounts, or remove
                  users. Passwords and TOTP secrets are never exposed by the API.
                </p>
              </div>
              <button
                onClick={loadAdminUsers}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 flex items-center gap-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" /> Refresh
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-3 px-3">Username & ID</th>
                    <th className="py-3 px-3">Full Name & Dept</th>
                    <th className="py-3 px-3">Role</th>
                    <th className="py-3 px-3">Status</th>
                    <th className="py-3 px-3">2FA</th>
                    <th className="py-3 px-3 text-right">Admin Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {adminUsers.map((u) => (
                    <tr key={u.id} className="hover:bg-slate-950/40">
                      <td className="py-3 px-3">
                        <div className="font-bold text-white">@{u.username}</div>
                        <div className="font-mono text-[11px] text-slate-400">
                          {u.studentOrStaffId}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <div className="text-slate-200">{u.fullName}</div>
                        <div className="text-[11px] text-slate-400">{u.department}</div>
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`px-2 py-0.5 rounded font-bold ${
                            u.role === 'ADMIN'
                              ? 'bg-amber-500/20 text-amber-300'
                              : 'bg-sky-500/20 text-sky-300'
                          }`}
                        >
                          {u.role}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`px-2 py-0.5 rounded font-bold ${
                            u.status === 'ACTIVE'
                              ? 'bg-emerald-500/20 text-emerald-300'
                              : 'bg-rose-500/20 text-rose-300'
                          }`}
                        >
                          {u.status}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        {u.twoFactorEnabled ? (
                          <span className="text-emerald-400 font-semibold">Enabled</span>
                        ) : (
                          <span className="text-slate-500">Off</span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-right space-x-2">
                        <button
                          onClick={() => handleToggleUserRole(u)}
                          disabled={u.id === currentUser.id}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 font-medium cursor-pointer"
                        >
                          Make {u.role === 'ADMIN' ? 'USER' : 'ADMIN'}
                        </button>
                        <button
                          onClick={() => handleToggleUserStatus(u)}
                          disabled={u.id === currentUser.id}
                          className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 disabled:opacity-40 text-amber-300 font-medium cursor-pointer"
                        >
                          {u.status === 'ACTIVE' ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          onClick={() => handleDeleteUser(u)}
                          disabled={u.id === currentUser.id}
                          className="p-1 rounded bg-rose-500/20 hover:bg-rose-500/30 disabled:opacity-40 text-rose-300 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5 inline" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ==================================================================
            VIEW 7: ADMIN SCHOOL NOTICEBOARD MANAGER
           ================================================================== */}
        {activeTab === 'ADMIN_NOTICES' && currentUser?.role === 'ADMIN' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <form
              onSubmit={handleCreateNotice}
              className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4"
            >
              <div className="flex items-center gap-2">
                <PlusCircle className="w-5 h-5 text-amber-400" />
                <h3 className="font-bold text-white text-base">
                  Publish NKETIAH Notice
                </h3>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Title
                </label>
                <input
                  type="text"
                  required
                  value={noticeTitle}
                  onChange={(e) => setNoticeTitle(e.target.value)}
                  placeholder="Notice headline"
                  className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Category
                  </label>
                  <select
                    value={noticeCategory}
                    onChange={(e) =>
                      setNoticeCategory(e.target.value as SchoolNotice['category'])
                    }
                    className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-xs"
                  >
                    <option value="ACADEMIC">ACADEMIC</option>
                    <option value="SECURITY">SECURITY</option>
                    <option value="ADMISSIONS">ADMISSIONS</option>
                    <option value="EXAMINATIONS">EXAMINATIONS</option>
                    <option value="GENERAL">GENERAL</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    RBAC Visibility
                  </label>
                  <select
                    value={noticeVisibility}
                    onChange={(e) =>
                      setNoticeVisibility(e.target.value as SchoolNotice['visibility'])
                    }
                    className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-xs"
                  >
                    <option value="PUBLIC">PUBLIC (Guests+)</option>
                    <option value="AUTHENTICATED_ONLY">USER & ADMIN</option>
                    <option value="ADMIN_ONLY">ADMIN ONLY</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Announcement Content
                </label>
                <textarea
                  rows={4}
                  required
                  value={noticeContent}
                  onChange={(e) => setNoticeContent(e.target.value)}
                  placeholder="Enter official school announcement..."
                  className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm"
                />
              </div>

              <button
                type="submit"
                className="w-full py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs transition cursor-pointer"
              >
                Publish Notice
              </button>
            </form>

            <div className="lg:col-span-2 rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
              <h3 className="font-bold text-white text-base">
                Active School Notices ({notices.length})
              </h3>
              <div className="space-y-3">
                {notices.map((n) => (
                  <div
                    key={n.id}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-start justify-between gap-4"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-emerald-400">
                          [{n.category}]
                        </span>
                        <span className="text-xs font-mono text-amber-300">
                          ({n.visibility})
                        </span>
                        <h4 className="font-bold text-white text-sm">{n.title}</h4>
                      </div>
                      <p className="text-xs text-slate-300">{n.content}</p>
                    </div>
                    <button
                      onClick={() => handleDeleteNotice(n.id)}
                      className="p-1.5 rounded-lg bg-rose-500/15 text-rose-400 hover:bg-rose-500/25"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================
            VIEW 8: ADMIN SECURITY AUDIT LOGS
           ================================================================== */}
        {activeTab === 'ADMIN_AUDIT_LOGS' && currentUser?.role === 'ADMIN' && (
          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <FileWarning className="w-5 h-5 text-amber-400" />
                <div>
                  <h2 className="text-lg font-bold text-white">
                    Immutable Security Audit Logs
                  </h2>
                  <p className="text-xs text-slate-400">
                    Tracks logins, 2FA events, role changes, unauthorized access attempts, and
                    backups without logging secrets.
                  </p>
                </div>
              </div>
              <button
                onClick={loadAuditLogs}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 flex items-center gap-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" /> Refresh Logs
              </button>
            </div>

            <div className="overflow-x-auto max-h-[520px]">
              <table className="w-full text-left border-collapse text-xs">
                <thead className="sticky top-0 bg-slate-900">
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Event Type</th>
                    <th className="py-2.5 px-3">Actor</th>
                    <th className="py-2.5 px-3">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-950/40">
                      <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                        {new Date(log.createdAt).toLocaleString()}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                            log.severity === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-300'
                              : log.severity === 'WARNING'
                              ? 'bg-amber-500/20 text-amber-300'
                              : 'bg-emerald-500/20 text-emerald-300'
                          }`}
                        >
                          {log.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono font-semibold text-white">
                        {log.eventType}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {log.actorUsername || 'Anonymous'}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{log.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ==================================================================
            VIEW 9: AUTOMATED DATABASE BACKUPS & 1-CLICK RECOVERY
           ================================================================== */}
        {activeTab === 'ADMIN_BACKUPS' && currentUser?.role === 'ADMIN' && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 flex flex-wrap items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Server className="w-5 h-5 text-emerald-400" />
                  <h2 className="text-lg font-bold text-white">
                    Automated Firestore Database Backups & Recovery Vault
                  </h2>
                </div>
                <p className="text-xs text-slate-400">
                  Every snapshot exports all Firestore collections, computes a SHA-256
                  checksum, and encrypts the payload using AES-256-GCM before storage.
                </p>
              </div>
              <button
                onClick={handleTriggerBackup}
                disabled={adminBusy}
                className="px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold text-xs flex items-center gap-2 cursor-pointer"
              >
                <Database className="w-4 h-4" />
                {adminBusy
                  ? 'Processing Encrypted Snapshot...'
                  : 'Create Encrypted Backup Now'}
              </button>
            </div>

            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-4">
              <h3 className="font-bold text-white text-sm">
                Backup History & Point-in-Time Restoration ({backups.length})
              </h3>
              <div className="space-y-3">
                {backups.map((b) => (
                  <div
                    key={b.id}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-4"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-sm text-emerald-400">
                          {b.filename}
                        </span>
                        <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold">
                          {b.triggerType}
                        </span>
                        <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-semibold">
                          {b.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 font-mono">
                        SHA-256: {b.checksumSha256}
                      </p>
                      <p className="text-xs text-slate-400">
                        Records: {b.collectionCounts.users} users,{' '}
                        {b.collectionCounts.schoolNotices} notices,{' '}
                        {b.collectionCounts.auditLogs} audit logs • Size: {b.sizeBytes} bytes •
                        Created: {new Date(b.createdAt).toLocaleString()}
                      </p>
                    </div>

                    <button
                      onClick={() => handleRestoreBackup(b.backupId, b.filename)}
                      disabled={adminBusy}
                      className="px-3.5 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 text-xs font-semibold transition cursor-pointer"
                    >
                      Restore Database from Snapshot
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </main>

      {/* FOOTER */}
      <footer className="border-t border-slate-900 py-4 text-center text-xs text-slate-500">
        NKETIAH School Management System • Information Security Academic Project • Argon2id +
        AES-256-GCM + TOTP 2FA + Firestore Backups
      </footer>
    </div>
  );
}
export default App;

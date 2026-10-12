import * as admin from 'firebase-admin';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { env } from './env';
import {
  AuditLogDocument,
  BackupLogDocument,
  RecoveryCodesDocument,
  SchoolNoticeDocument,
  SessionDocument,
  UserDocument,
} from '../types/models';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - FIREBASE ADMIN SDK & FIRESTORE ADAPTER
 * ============================================================================
 *
 * TEACHING NOTE:
 * Why do we use Firebase Admin SDK on the Node.js server instead of the
 * Firebase Client SDK in React/Expo?
 * 1. Centralized Security Authority: The Node.js server enforces Argon2id
 *    hashing with our secret server-side Pepper, AES-256-GCM encryption for
 *    TOTP secrets, and Role-Based Access Control (GUEST / USER / ADMIN).
 * 2. Zero Client Exposure: Neither React Web nor Expo Mobile ever receives
 *    database credentials or direct read/write permissions to Firestore.
 *
 * DUAL-ENGINE CAPABILITY (Cloud Firestore + Local Firestore Mirror):
 * - When `serviceAccountKey.json`, `FIREBASE_SERVICE_ACCOUNT_JSON`, or
 *   `FIRESTORE_EMULATOR_HOST` is present, all operations execute directly
 *   against Google Cloud Firestore & Firebase Cloud Storage (`gs://...`).
 * - In local development or automated test suites without an active cloud
 *   service account file, it seamlessly operates using a Firestore-compatible
 *   document engine persisted at `backend/data/firestore-collections.json`.
 */

export interface FirestoreCollectionsState {
  users: Record<string, UserDocument>;
  sessions: Record<string, SessionDocument>;
  recoveryCodes: Record<string, RecoveryCodesDocument>;
  schoolNotices: Record<string, SchoolNoticeDocument>;
  auditLogs: Record<string, AuditLogDocument>;
  backupLogs: Record<string, BackupLogDocument>;
}

export type CollectionName = keyof FirestoreCollectionsState;

const isServerless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
const BUNDLED_DATA_FILE = path.resolve(__dirname, '../../data/firestore-collections.json');
const DATA_DIR = isServerless
  ? path.join(os.tmpdir(), 'nketiah-data')
  : path.resolve(__dirname, '../../data');
const LOCAL_FIRESTORE_FILE = path.join(DATA_DIR, 'firestore-collections.json');
export const BACKUPS_DIR = isServerless
  ? path.join(os.tmpdir(), 'nketiah-backups')
  : path.resolve(__dirname, '../../backups');

try {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(BACKUPS_DIR)) {
    fs.mkdirSync(BACKUPS_DIR, { recursive: true });
  }
  if (isServerless && !fs.existsSync(LOCAL_FIRESTORE_FILE) && fs.existsSync(BUNDLED_DATA_FILE)) {
    fs.copyFileSync(BUNDLED_DATA_FILE, LOCAL_FIRESTORE_FILE);
  }
} catch {
  // Ignore filesystem init errors in restricted environments
}

let firestoreInstance: admin.firestore.Firestore | null = null;
let storageBucketInstance: ReturnType<admin.storage.Storage['bucket']> | null = null;
let isCloudFirestoreConnected = false;

function initializeFirebaseAdmin(): void {
  try {
    if (env.NODE_ENV === 'test') {
      // During automated unit/integration tests, use isolated in-memory/file state
      isCloudFirestoreConnected = false;
      return;
    }

    let credential: admin.credential.Credential | undefined;

    if (env.FIREBASE_SERVICE_ACCOUNT_JSON && env.FIREBASE_SERVICE_ACCOUNT_JSON.trim().startsWith('{')) {
      const parsedCert = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_JSON);
      credential = admin.credential.cert(parsedCert);
    } else if (env.GOOGLE_APPLICATION_CREDENTIALS) {
      const credPath = path.resolve(__dirname, '../../', env.GOOGLE_APPLICATION_CREDENTIALS);
      if (fs.existsSync(credPath)) {
        const parsedCert = JSON.parse(fs.readFileSync(credPath, 'utf-8'));
        credential = admin.credential.cert(parsedCert);
      }
    }

    if (credential || process.env.FIRESTORE_EMULATOR_HOST) {
      if (admin.apps.length === 0) {
        admin.initializeApp({
          credential: credential || admin.credential.applicationDefault(),
          projectId: env.FIREBASE_PROJECT_ID,
          storageBucket: env.FIREBASE_STORAGE_BUCKET,
        });
      }
      firestoreInstance = admin.firestore();
      firestoreInstance.settings({ ignoreUndefinedProperties: true });

      try {
        storageBucketInstance = admin.storage().bucket(env.FIREBASE_STORAGE_BUCKET);
      } catch {
        storageBucketInstance = null;
      }

      isCloudFirestoreConnected = true;
      console.log(
        `✅ [Firebase Admin] Connected to Google Cloud Firestore (Project: ${env.FIREBASE_PROJECT_ID})`
      );
    } else {
      isCloudFirestoreConnected = false;
      console.log(
        `ℹ️ [Firebase Admin] No serviceAccountKey.json detected yet. Running in Firestore-Compatible Local Cloud Mirror mode (${LOCAL_FIRESTORE_FILE}).`
      );
    }
  } catch (error) {
    isCloudFirestoreConnected = false;
    console.warn(
      '⚠️ [Firebase Admin] Falling back to Firestore-Compatible Local Mirror:',
      (error as Error).message
    );
  }
}

initializeFirebaseAdmin();

// In-memory cache synchronized with local disk when running in mirror/test mode
let localState: FirestoreCollectionsState = {
  users: {},
  sessions: {},
  recoveryCodes: {},
  schoolNotices: {},
  auditLogs: {},
  backupLogs: {},
};

function loadLocalState(): void {
  if (env.NODE_ENV === 'test') return;
  if (fs.existsSync(LOCAL_FIRESTORE_FILE)) {
    try {
      const raw = fs.readFileSync(LOCAL_FIRESTORE_FILE, 'utf-8');
      const parsed = JSON.parse(raw);
      localState = {
        users: parsed.users || {},
        sessions: parsed.sessions || {},
        recoveryCodes: parsed.recoveryCodes || {},
        schoolNotices: parsed.schoolNotices || {},
        auditLogs: parsed.auditLogs || {},
        backupLogs: parsed.backupLogs || {},
      };
    } catch {
      // Keep clean default state if corrupted
    }
  }
}

function saveLocalState(): void {
  if (env.NODE_ENV === 'test') return;
  fs.writeFileSync(LOCAL_FIRESTORE_FILE, JSON.stringify(localState, null, 2), 'utf-8');
}

loadLocalState();

/**
 * Unified Firestore Document Repository
 * Provides clean async CRUD and transactional queries across all 6 Firestore collections.
 */
export const firestoreRepo = {
  isCloudActive(): boolean {
    return isCloudFirestoreConnected && firestoreInstance !== null;
  },

  getStorageBucket() {
    return storageBucketInstance;
  },

  getConnectionInfo() {
    return {
      mode: this.isCloudActive() ? 'GOOGLE_CLOUD_FIRESTORE' : 'FIRESTORE_LOCAL_CLOUD_MIRROR',
      projectId: env.FIREBASE_PROJECT_ID,
      storageBucket: env.FIREBASE_STORAGE_BUCKET,
      cloudConnected: this.isCloudActive(),
    };
  },

  async getDoc<K extends CollectionName>(
    collection: K,
    docId: string
  ): Promise<FirestoreCollectionsState[K][string] | null> {
    if (this.isCloudActive() && firestoreInstance) {
      const snap = await firestoreInstance.collection(collection).doc(docId).get();
      if (!snap.exists) return null;
      return snap.data() as FirestoreCollectionsState[K][string];
    }
    const doc = localState[collection][docId];
    return doc ? (structuredClone(doc) as FirestoreCollectionsState[K][string]) : null;
  },

  async setDoc<K extends CollectionName>(
    collection: K,
    docId: string,
    data: FirestoreCollectionsState[K][string]
  ): Promise<void> {
    if (this.isCloudActive() && firestoreInstance) {
      await firestoreInstance.collection(collection).doc(docId).set(data);
    }
    localState[collection][docId] = structuredClone(data);
    saveLocalState();
  },

  async updateDoc<K extends CollectionName>(
    collection: K,
    docId: string,
    partialData: Partial<FirestoreCollectionsState[K][string]>
  ): Promise<FirestoreCollectionsState[K][string] | null> {
    if (this.isCloudActive() && firestoreInstance) {
      await firestoreInstance
        .collection(collection)
        .doc(docId)
        .set(partialData as Record<string, unknown>, { merge: true });
      const updated = await this.getDoc(collection, docId);
      if (updated) {
        localState[collection][docId] = structuredClone(updated);
        saveLocalState();
      }
      return updated;
    }

    const existing = localState[collection][docId];
    if (!existing) return null;
    const merged = { ...existing, ...partialData } as FirestoreCollectionsState[K][string];
    localState[collection][docId] = structuredClone(merged);
    saveLocalState();
    return structuredClone(merged) as FirestoreCollectionsState[K][string];
  },

  async deleteDoc<K extends CollectionName>(collection: K, docId: string): Promise<boolean> {
    if (this.isCloudActive() && firestoreInstance) {
      await firestoreInstance.collection(collection).doc(docId).delete();
    }
    const existed = Boolean(localState[collection][docId]);
    delete localState[collection][docId];
    saveLocalState();
    return existed;
  },

  async listDocs<K extends CollectionName>(
    collection: K
  ): Promise<Array<FirestoreCollectionsState[K][string]>> {
    if (this.isCloudActive() && firestoreInstance) {
      const snapshot = await firestoreInstance.collection(collection).get();
      const docs = snapshot.docs.map((d) => d.data() as FirestoreCollectionsState[K][string]);
      return docs;
    }
    return Object.values(localState[collection]).map((d) => structuredClone(d));
  },

  async findUserByUsername(username: string): Promise<UserDocument | null> {
    const normalized = username.trim().toLowerCase();
    if (this.isCloudActive() && firestoreInstance) {
      const snap = await firestoreInstance
        .collection('users')
        .where('usernameNormalized', '==', normalized)
        .limit(1)
        .get();
      if (snap.empty) return null;
      return snap.docs[0].data() as UserDocument;
    }

    const users = Object.values(localState.users);
    const found = users.find((u) => u.usernameNormalized === normalized);
    return found ? structuredClone(found) : null;
  },

  /**
   * Export entire database state (used by Automated Backup Service)
   */
  async exportFullDatabaseSnapshot(): Promise<Omit<FirestoreCollectionsState, 'backupLogs'>> {
    const [users, sessions, recoveryCodes, schoolNotices, auditLogs] = await Promise.all([
      this.listDocs('users'),
      this.listDocs('sessions'),
      this.listDocs('recoveryCodes'),
      this.listDocs('schoolNotices'),
      this.listDocs('auditLogs'),
    ]);

    return {
      users: Object.fromEntries(users.map((u) => [u.id, u])),
      sessions: Object.fromEntries(sessions.map((s) => [s.id, s])),
      recoveryCodes: Object.fromEntries(recoveryCodes.map((r) => [r.id, r])),
      schoolNotices: Object.fromEntries(schoolNotices.map((n) => [n.id, n])),
      auditLogs: Object.fromEntries(auditLogs.map((a) => [a.id, a])),
    };
  },

  /**
   * Restore full database snapshot (used by Database Restoration Service)
   */
  async restoreFullDatabaseSnapshot(
    snapshot: Omit<FirestoreCollectionsState, 'backupLogs'>
  ): Promise<void> {
    const collectionsToRestore: Array<Exclude<CollectionName, 'backupLogs'>> = [
      'users',
      'sessions',
      'recoveryCodes',
      'schoolNotices',
      'auditLogs',
    ];

    if (this.isCloudActive() && firestoreInstance) {
      for (const colName of collectionsToRestore) {
        const existingSnap = await firestoreInstance.collection(colName).get();
        const batchDelete = firestoreInstance.batch();
        existingSnap.docs.forEach((doc) => batchDelete.delete(doc.ref));
        await batchDelete.commit();

        const docsMap = snapshot[colName] as Record<string, unknown>;
        const batchWrite = firestoreInstance.batch();
        for (const [docId, docData] of Object.entries(docsMap)) {
          const ref = firestoreInstance.collection(colName).doc(docId);
          batchWrite.set(ref, docData as Record<string, unknown>);
        }
        await batchWrite.commit();
      }
    }

    localState.users = structuredClone(snapshot.users || {});
    localState.sessions = structuredClone(snapshot.sessions || {});
    localState.recoveryCodes = structuredClone(snapshot.recoveryCodes || {});
    localState.schoolNotices = structuredClone(snapshot.schoolNotices || {});
    localState.auditLogs = structuredClone(snapshot.auditLogs || {});
    saveLocalState();
  },

  /**
   * Reset all collections (exclusively for automated test isolation)
   */
  async clearAllForTesting(): Promise<void> {
    if (env.NODE_ENV !== 'test') {
      throw new Error('clearAllForTesting is strictly restricted to NODE_ENV=test');
    }
    localState = {
      users: {},
      sessions: {},
      recoveryCodes: {},
      schoolNotices: {},
      auditLogs: {},
      backupLogs: {},
    };
  },
};

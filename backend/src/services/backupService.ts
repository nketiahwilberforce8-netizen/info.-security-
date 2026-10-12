import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import cron from 'node-cron';
import { env } from '../config/env';
import { BACKUPS_DIR, firestoreRepo, FirestoreCollectionsState } from '../config/firebase';
import { AesGcmEncryptedPayload, BackupLogDocument } from '../types/models';
import { decryptAes256Gcm, encryptAes256Gcm } from './encryptionService';
import { recordAuditLog } from './auditService';

/**
 * ============================================================================
 * NKETIAH SCHOOL MANAGEMENT SYSTEM - AUTOMATED BACKUP & RESTORATION ENGINE
 * ============================================================================
 *
 * Implements:
 * 1. Scheduled Automated Firestore Backups via `node-cron`
 * 2. Manual CLI & Admin API Backups
 * 3. AES-256-GCM Encryption of all backup snapshots
 * 4. SHA-256 Integrity Checksum verification
 * 5. Upload to Google Cloud Storage / Firebase Storage + Local Encrypted Vault
 * 6. Full Database Restoration & Recovery with integrity verification
 */

export interface EncryptedBackupArchiveFile {
  backupId: string;
  schoolSystem: string;
  createdAt: string;
  triggerType: 'AUTOMATED_CRON' | 'MANUAL_CLI' | 'ADMIN_API';
  triggeredByUsername: string;
  checksumSha256: string;
  collectionCounts: {
    users: number;
    sessions: number;
    recoveryCodes: number;
    schoolNotices: number;
    auditLogs: number;
  };
  encryptedPayload: AesGcmEncryptedPayload;
}

export async function createDatabaseBackup(options: {
  triggerType: 'AUTOMATED_CRON' | 'MANUAL_CLI' | 'ADMIN_API';
  triggeredByUsername?: string;
}): Promise<BackupLogDocument> {
  const timestamp = new Date().toISOString();
  const safeTime = timestamp.replace(/[:.]/g, '-');
  const backupId = `bkp_${safeTime}_${crypto.randomBytes(3).toString('hex')}`;
  const filename = `${backupId}.enc.json`;
  const localFilePath = path.join(BACKUPS_DIR, filename);
  const triggeredBy = options.triggeredByUsername || 'SYSTEM_CRON';

  try {
    // 1. Export all collections from Firestore
    const snapshot = await firestoreRepo.exportFullDatabaseSnapshot();

    const collectionCounts = {
      users: Object.keys(snapshot.users).length,
      sessions: Object.keys(snapshot.sessions).length,
      recoveryCodes: Object.keys(snapshot.recoveryCodes).length,
      schoolNotices: Object.keys(snapshot.schoolNotices).length,
      auditLogs: Object.keys(snapshot.auditLogs).length,
    };

    const rawSnapshotJson = JSON.stringify(snapshot);

    // 2. Compute SHA-256 Integrity Checksum of plaintext snapshot
    const checksumSha256 = crypto
      .createHash('sha256')
      .update(rawSnapshotJson, 'utf8')
      .digest('hex');

    // 3. Encrypt snapshot using AES-256-GCM
    const encryptedPayload = encryptAes256Gcm(rawSnapshotJson);

    const archiveFileContent: EncryptedBackupArchiveFile = {
      backupId,
      schoolSystem: env.SCHOOL_NAME,
      createdAt: timestamp,
      triggerType: options.triggerType,
      triggeredByUsername: triggeredBy,
      checksumSha256,
      collectionCounts,
      encryptedPayload,
    };

    const serializedArchive = JSON.stringify(archiveFileContent, null, 2);
    const sizeBytes = Buffer.byteLength(serializedArchive, 'utf8');

    // 4. Write to Local Encrypted Vault (`backend/backups/*.enc.json`)
    fs.writeFileSync(localFilePath, serializedArchive, 'utf8');

    // 5. Upload to Firebase Cloud Storage / Google Cloud Storage if active
    let storageLocation: BackupLogDocument['storageLocation'] = 'LOCAL_ENCRYPTED_VAULT';
    let cloudBucketPath: string | null = null;

    const bucket = firestoreRepo.getStorageBucket();
    if (firestoreRepo.isCloudActive() && bucket) {
      try {
        const destination = `nketiah-backups/${filename}`;
        const fileRef = bucket.file(destination);
        await fileRef.save(serializedArchive, {
          contentType: 'application/json',
          metadata: {
            backupId,
            checksumSha256,
            encryption: 'aes-256-gcm',
          },
        });
        storageLocation = 'FIREBASE_CLOUD_STORAGE_AND_LOCAL';
        cloudBucketPath = `gs://${env.FIREBASE_STORAGE_BUCKET}/${destination}`;
      } catch {
        // If Firebase project is on Spark plan without active GCS bucket, local encrypted vault succeeds cleanly
        storageLocation = 'LOCAL_ENCRYPTED_VAULT';
      }
    }

    const backupLog: BackupLogDocument = {
      id: backupId,
      backupId,
      filename,
      triggerType: options.triggerType,
      status: 'SUCCESS',
      storageLocation,
      cloudBucketPath,
      localFilePath,
      sizeBytes,
      checksumSha256,
      encryptionAlgorithm: 'aes-256-gcm',
      collectionCounts,
      triggeredByUsername: triggeredBy,
      errorMessage: null,
      createdAt: timestamp,
      restoredAt: null,
    };

    await firestoreRepo.setDoc('backupLogs', backupId, backupLog);

    await recordAuditLog({
      eventType: 'BACKUP_CREATED',
      severity: 'INFO',
      actorUsername: triggeredBy,
      details: `Encrypted database backup ${filename} created (${sizeBytes} bytes, SHA-256 verified).`,
      metadata: {
        backupId,
        triggerType: options.triggerType,
        usersCount: collectionCounts.users,
        storageLocation,
      },
    });

    // Enforce retention policy on old backups
    await enforceBackupRetention();

    return backupLog;
  } catch (error) {
    const errMsg = (error as Error).message || 'Unknown backup error';
    const failedLog: BackupLogDocument = {
      id: backupId,
      backupId,
      filename,
      triggerType: options.triggerType,
      status: 'FAILED',
      storageLocation: 'LOCAL_ENCRYPTED_VAULT',
      cloudBucketPath: null,
      localFilePath,
      sizeBytes: 0,
      checksumSha256: '',
      encryptionAlgorithm: 'aes-256-gcm',
      collectionCounts: {
        users: 0,
        sessions: 0,
        recoveryCodes: 0,
        schoolNotices: 0,
        auditLogs: 0,
      },
      triggeredByUsername: triggeredBy,
      errorMessage: errMsg,
      createdAt: timestamp,
      restoredAt: null,
    };

    await firestoreRepo.setDoc('backupLogs', backupId, failedLog);

    await recordAuditLog({
      eventType: 'BACKUP_FAILED',
      severity: 'CRITICAL',
      actorUsername: triggeredBy,
      details: `Database backup failed: ${errMsg}`,
      metadata: { backupId, triggerType: options.triggerType },
    });

    throw error;
  }
}

/**
 * Restores the Firestore database from an AES-256-GCM encrypted backup archive.
 * Verifies both the 128-bit AES-GCM Authentication Tag AND the SHA-256 Checksum
 * before modifying the database.
 */
export async function restoreDatabaseFromBackup(
  backupId: string,
  triggeredByUsername: string = 'ADMIN'
): Promise<{
  backupLog: BackupLogDocument;
  restoredCounts: BackupLogDocument['collectionCounts'];
}> {
  const backupLog = await firestoreRepo.getDoc('backupLogs', backupId);
  if (!backupLog) {
    throw new Error(`Backup ID '${backupId}' not found in backup logs.`);
  }

  let rawArchiveJson: string | null = null;

  // 1. Load from Local Encrypted Vault or Firebase Cloud Storage
  if (fs.existsSync(backupLog.localFilePath)) {
    rawArchiveJson = fs.readFileSync(backupLog.localFilePath, 'utf8');
  } else if (firestoreRepo.isCloudActive() && firestoreRepo.getStorageBucket()) {
    const bucket = firestoreRepo.getStorageBucket()!;
    const destination = `nketiah-backups/${backupLog.filename}`;
    const [buffer] = await bucket.file(destination).download();
    rawArchiveJson = buffer.toString('utf8');
  }

  if (!rawArchiveJson) {
    throw new Error(`Encrypted backup archive file (${backupLog.filename}) could not be found.`);
  }

  const archive: EncryptedBackupArchiveFile = JSON.parse(rawArchiveJson);

  // 2. Decrypt using AES-256-GCM (automatically verifies 128-bit GCM authTag)
  const decryptedJson = decryptAes256Gcm(archive.encryptedPayload);

  // 3. Verify SHA-256 integrity checksum
  const computedChecksum = crypto
    .createHash('sha256')
    .update(decryptedJson, 'utf8')
    .digest('hex');

  if (computedChecksum !== archive.checksumSha256) {
    throw new Error(
      'CRITICAL INTEGRITY ERROR: Backup SHA-256 checksum mismatch! Restoration aborted.'
    );
  }

  const snapshot = JSON.parse(decryptedJson) as Omit<
    FirestoreCollectionsState,
    'backupLogs'
  >;

  // 4. Restore collections into Firestore
  await firestoreRepo.restoreFullDatabaseSnapshot(snapshot);

  const restoredAt = new Date().toISOString();
  const updatedLog = await firestoreRepo.updateDoc('backupLogs', backupId, {
    status: 'RESTORED',
    restoredAt,
  });

  await recordAuditLog({
    eventType: 'DATABASE_RESTORED',
    severity: 'WARNING',
    actorUsername: triggeredByUsername,
    details: `Database successfully restored from encrypted backup ${backupLog.filename}.`,
    metadata: {
      backupId,
      restoredUsers: archive.collectionCounts.users,
      restoredNotices: archive.collectionCounts.schoolNotices,
    },
  });

  return {
    backupLog: updatedLog || backupLog,
    restoredCounts: archive.collectionCounts,
  };
}

export async function listBackupLogs(): Promise<BackupLogDocument[]> {
  const logs = await firestoreRepo.listDocs('backupLogs');
  return logs.sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
}

async function enforceBackupRetention(): Promise<void> {
  const all = await listBackupLogs();
  if (all.length <= env.BACKUP_RETENTION_COUNT) return;

  const toPrune = all.slice(env.BACKUP_RETENTION_COUNT);
  for (const oldBackup of toPrune) {
    if (fs.existsSync(oldBackup.localFilePath)) {
      try {
        fs.unlinkSync(oldBackup.localFilePath);
      } catch {
        // Ignore file deletion error
      }
    }
    await firestoreRepo.deleteDoc('backupLogs', oldBackup.id);
  }
}

let scheduledCronTask: cron.ScheduledTask | null = null;

/**
 * Starts the automated background cron job for Firestore database backups.
 */
export function startAutomatedBackupScheduler(): void {
  if (scheduledCronTask) return;

  if (!cron.validate(env.BACKUP_CRON_SCHEDULE)) {
    console.warn(`⚠️ [Backup Scheduler] Invalid cron expression: ${env.BACKUP_CRON_SCHEDULE}`);
    return;
  }

  scheduledCronTask = cron.schedule(env.BACKUP_CRON_SCHEDULE, async () => {
    try {
      console.log('⏰ [Automated Backup] Running scheduled Firestore encrypted backup...');
      const result = await createDatabaseBackup({
        triggerType: 'AUTOMATED_CRON',
        triggeredByUsername: 'SYSTEM_CRON_SCHEDULER',
      });
      console.log(`✅ [Automated Backup] Completed: ${result.filename}`);
    } catch (err) {
      console.error('❌ [Automated Backup] Failed:', (err as Error).message);
    }
  });

  console.log(
    `🛡️ [Backup Scheduler] Automated Firestore backups scheduled (${env.BACKUP_CRON_SCHEDULE})`
  );
}

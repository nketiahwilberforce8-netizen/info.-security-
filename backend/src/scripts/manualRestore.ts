import { listBackupLogs, restoreDatabaseFromBackup } from '../services/backupService';

/**
 * CLI Manual Restore Command (`npm run restore [optional_backup_id]`)
 * Restores the latest (or specified) AES-256-GCM encrypted backup and verifies its SHA-256 checksum.
 */
async function runManualRestoreCli(): Promise<void> {
  const requestedBackupId = process.argv[2];
  const allBackups = await listBackupLogs();

  if (allBackups.length === 0) {
    console.error('❌ [NKETIAH Restore CLI] No backups found. Run `npm run backup` first.');
    process.exit(1);
  }

  const targetBackupId = requestedBackupId || allBackups[0].backupId;
  console.log(`🔄 [NKETIAH Restore CLI] Restoring database from backup: ${targetBackupId}...`);

  const result = await restoreDatabaseFromBackup(targetBackupId, 'CLI_OPERATOR');

  console.log('✅ [NKETIAH Restore CLI] Database Restoration & Integrity Verification Complete!');
  console.log('-------------------------------------------------------------------------');
  console.log(`Restored Backup ID : ${result.backupLog.backupId}`);
  console.log(`Filename           : ${result.backupLog.filename}`);
  console.log(`SHA-256 Verified   : ${result.backupLog.checksumSha256}`);
  console.log(`Restored Records   :`, result.restoredCounts);
  console.log('-------------------------------------------------------------------------');
}

runManualRestoreCli().catch((err) => {
  console.error('❌ [NKETIAH Restore CLI] Error:', err);
  process.exit(1);
});

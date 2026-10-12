import { createDatabaseBackup } from '../services/backupService';
import { ensureDefaultNketiahSeedData } from '../services/seedService';

/**
 * CLI Manual Backup Command (`npm run backup`)
 * Allows the student or administrator to trigger an encrypted Firestore backup from the terminal.
 */
async function runManualBackupCli(): Promise<void> {
  console.log('🛡️ [NKETIAH Backup CLI] Ensuring initial seed state & starting encrypted backup...');
  await ensureDefaultNketiahSeedData();

  const backupLog = await createDatabaseBackup({
    triggerType: 'MANUAL_CLI',
    triggeredByUsername: 'CLI_OPERATOR',
  });

  console.log('✅ [NKETIAH Backup CLI] Encrypted Firestore Backup Created Successfully!');
  console.log('-------------------------------------------------------------------------');
  console.log(`Backup ID         : ${backupLog.backupId}`);
  console.log(`Encrypted File    : ${backupLog.localFilePath}`);
  console.log(`Storage Location  : ${backupLog.storageLocation}`);
  console.log(`Encryption        : ${backupLog.encryptionAlgorithm.toUpperCase()} (96-bit IV + 128-bit Auth Tag)`);
  console.log(`SHA-256 Checksum  : ${backupLog.checksumSha256}`);
  console.log(`Size              : ${backupLog.sizeBytes} bytes`);
  console.log(`Collection Counts :`, backupLog.collectionCounts);
  console.log('-------------------------------------------------------------------------');
}

runManualBackupCli().catch((err) => {
  console.error('❌ [NKETIAH Backup CLI] Error:', err);
  process.exit(1);
});

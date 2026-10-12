import { app } from './app';
import { env } from './config/env';
import { startAutomatedBackupScheduler } from './services/backupService';
import { ensureDefaultNketiahSeedData } from './services/seedService';

async function bootstrapServer(): Promise<void> {
  await ensureDefaultNketiahSeedData();
  startAutomatedBackupScheduler();

  app.listen(env.PORT, () => {
    console.log('============================================================================');
    console.log(`🎓 ${env.SCHOOL_NAME}`);
    console.log(`🚀 Central Node.js Security API listening on http://localhost:${env.PORT}`);
    console.log(`🔐 Security: Argon2id (Salt+Pepper) | AES-256-GCM | TOTP 2FA | RBAC`);
    console.log('============================================================================');
  });
}

bootstrapServer().catch((err) => {
  console.error('❌ Failed to start NKETIAH Security API:', err);
  process.exit(1);
});

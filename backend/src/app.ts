import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import { env } from './config/env';
import { firestoreRepo } from './config/firebase';
import { generalApiLimiter } from './middleware/rateLimiter';
import { apiRouter } from './routes/apiRoutes';

export const app = express();

// 1. Helmet HTTP Security Headers (XSS protection, HSTS, X-Frame-Options, Content-Security-Policy)
app.use(helmet());

// 2. CORS Policy supporting both React Web (with credentials/cookies) & Expo Mobile
const allowedOrigins = env.CORS_ORIGINS.split(',').map((o) => o.trim());
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow mobile apps / curl / server-to-server requests with no origin header
      if (!origin || allowedOrigins.includes(origin) || env.NODE_ENV !== 'production') {
        callback(null, true);
      } else {
        callback(new Error('Origin not permitted by NKETIAH CORS Security Policy.'));
      }
    },
    credentials: true,
  })
);

// 3. Body & Cookie Parsing with strict payload size limit (prevents DoS memory exhaustion)
app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());

// 4. General Rate Limiting
app.use('/api', generalApiLimiter);

// 5. System Health & Cryptographic Status Endpoint
app.get('/api/health', (_req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    system: env.SCHOOL_NAME,
    status: 'OPERATIONAL',
    timestamp: new Date().toISOString(),
    database: firestoreRepo.getConnectionInfo(),
    securityControls: {
      passwordHashing: 'Argon2id + Unique 128-bit Salt + 256-bit Server Pepper',
      twoFactorAuth: 'RFC 6238 TOTP + Hashed One-Time Recovery Codes',
      encryption: 'AES-256-GCM (96-bit IV + 128-bit Auth Tag)',
      authorization: 'RBAC (GUEST, USER, ADMIN)',
      automatedBackups: `Scheduled (${env.BACKUP_CRON_SCHEDULE})`,
    },
  });
});

// 6. Mount Main REST API Router
app.use('/api', apiRouter);

// 7. 404 Handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    error: `Route ${req.method} ${req.originalUrl} not found on NKETIAH Security API.`,
  });
});

// 8. Global Secure Error Handler (Never leaks stack traces or secrets to clients)
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  if (env.NODE_ENV !== 'test') {
    console.error('⚠️ [API Error]:', err.message);
  }
  res.status(500).json({
    success: false,
    error: 'An unexpected internal security server error occurred.',
  });
});

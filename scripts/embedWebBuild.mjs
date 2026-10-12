import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const distDir = path.resolve(__dirname, '../web/dist');
const outTsFile = path.resolve(__dirname, '../backend/src/webBundle.ts');

function getContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.html') return 'text/html; charset=utf-8';
  if (ext === '.css') return 'text/css; charset=utf-8';
  if (ext === '.js' || ext === '.mjs') return 'application/javascript; charset=utf-8';
  if (ext === '.json') return 'application/json; charset=utf-8';
  if (ext === '.svg') return 'image/svg+xml';
  if (ext === '.ico') return 'image/x-icon';
  return 'application/octet-stream';
}

function walkFiles(dir, baseDir = dir, map = {}) {
  if (!fs.existsSync(dir)) return map;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkFiles(fullPath, baseDir, map);
    } else {
      const relUrl = '/' + path.relative(baseDir, fullPath).split(path.sep).join('/');
      const content = fs.readFileSync(fullPath, 'utf8');
      map[relUrl] = {
        contentType: getContentType(fullPath),
        content,
      };
    }
  }
  return map;
}

const assetsMap = walkFiles(distDir);

const tsSource = `// AUTO-GENERATED FULL-STACK WEB BUNDLE FOR VERCEL DEPLOYMENT
export interface BundledWebAsset {
  contentType: string;
  content: string;
}

export const WEB_BUNDLE: Record<string, BundledWebAsset> = ${JSON.stringify(assetsMap, null, 2)};
`;

fs.writeFileSync(outTsFile, tsSource, 'utf8');
console.log(`✅ Embedded ${Object.keys(assetsMap).length} web build files into backend/src/webBundle.ts`);

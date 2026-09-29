// Bundles the web app with esbuild and writes build.json with the SHA-256 of app.js, so the running code
// can be compared with a published fingerprint (see the "Verify this software" page).
import { build } from 'esbuild';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'web', 'dist');
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

await build({
  entryPoints: [path.join(root, 'web/src/main.js')], outfile: path.join(dist, 'app.js'), bundle: true, format: 'esm', platform: 'browser', target: 'es2022',
  minify: true, legalComments: 'none', logLevel: 'warning', loader: { '.md': 'text' }, define: { 'process.env.NODE_ENV': '"production"' },
});
cpSync(path.join(root, 'web/index.html'), path.join(dist, 'index.html'));
cpSync(path.join(root, 'web/style.css'), path.join(dist, 'style.css'));

const sha = createHash('sha256').update(readFileSync(path.join(dist, 'app.js'))).digest('hex');
const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
writeFileSync(path.join(dist, 'build.json'), JSON.stringify({ name: 'Project Ludlow', version: pkg.version, appSha256: sha }));
console.log(`built web/dist  app.js sha-256 ${sha}`);

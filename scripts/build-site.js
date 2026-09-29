// Builds the static project site (GitHub Pages) into site-dist/: bundles the "Try the lock" demo, which reuses
// the app's real cryptography, and copies the page, styles and screenshots. Nothing here loads anything from anywhere.
import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'site-dist');
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

await build({
  entryPoints: [path.join(root, 'site/src/try.js')], outfile: path.join(out, 'try.js'),
  bundle: true, format: 'esm', platform: 'browser', target: 'es2022', minify: true, legalComments: 'none', logLevel: 'warning',
});
for (const f of ['index.html', 'site.css', 'site.js']) cpSync(path.join(root, 'site', f), path.join(out, f));
cpSync(path.join(root, 'site/img'), path.join(out, 'img'), { recursive: true });
writeFileSync(path.join(out, '.nojekyll'), ''); // publish files as they are; no Jekyll processing
console.log('built site-dist');

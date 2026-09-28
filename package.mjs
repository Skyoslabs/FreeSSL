import { zipSync } from 'fflate';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const root = path.dirname(fileURLToPath(import.meta.url));
const files = {};
for (const [name, source] of Object.entries({ 'freessl.html': 'freessl.html', 'freessl.php': 'freessl.php', 'readme.md': 'docs/usage.md' })) {
  if (!/^[a-z0-9.-]+$/.test(name)) throw new Error('Installer filenames must use lowercase ASCII.');
  files[name] = [new Uint8Array(await readFile(path.join(root, source))), { mtime: new Date(1980, 0, 1) }];
}
await mkdir(path.join(root, 'dist'), { recursive: true });
await writeFile(path.join(root, 'dist', 'freessl.zip'), zipSync(files, { level: 6 }));
console.log('Created freessl.zip with two runtime files and the user guide.');

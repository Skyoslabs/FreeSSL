import { build } from 'esbuild';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const root = path.dirname(fileURLToPath(import.meta.url));
const { version } = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) throw new Error('Invalid application version.');
const result = await build({
  absWorkingDir: root, entryPoints: ['src/app.js'], bundle: true,
  platform: 'browser', format: 'iife', target: 'es2022', minify: true,
  write: false, legalComments: 'none'
});
const code = result.outputFiles[0].text.trim().replace(/<\/script/gi, '<\\/script');
const hash = createHash('sha256').update(code).digest('base64');
const escape = text => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const licenses = [
  await readFile(path.join(root, 'LICENSE'), 'utf8'),
  await readFile(path.join(root, 'vendor/fishball-acme/LICENSE'), 'utf8'),
  await readFile(path.join(root, 'node_modules/fflate/LICENSE'), 'utf8'),
  await readFile(path.join(root, 'vendor/acmecert/LICENSE.md'), 'utf8')
];
let page = await readFile(path.join(root, 'src/page.html'), 'utf8');
page = page.replace(/^[ \t]*<!-- TEMPLATE_NOTICE_START -->[\s\S]*?<!-- TEMPLATE_NOTICE_END -->[ \t]*\r?\n/m, '')
  .replaceAll('__APP_VERSION__', version)
  .replace('__SCRIPT_HASH__', () => hash).replace('__LICENSES__', () => escape(licenses.join('\n\n'))).replace('__BUNDLE__', () => code);
const destination = path.join(root, 'freessl.html');
await writeFile(destination, page);
let php = '<?php\ndeclare(strict_types=1);\n// Free SSL v' + version + '\n/*\n' + await readFile(path.join(root, 'LICENSE'), 'utf8') + '\n*/\n';
for (const file of ['ACME_Exception.php', 'ACMEv2.php', 'ACMECert.php']) {
  const source = await readFile(path.join(root, 'vendor/acmecert/src', file), 'utf8');
  php += source.replace(/^<\?php\s*/, '').replace('namespace skoerfgen\\ACMECert;', 'namespace skoerfgen\\ACMECert {') + '\n}\n';
}
php += '\nnamespace {\n' + (await readFile(path.join(root, 'src/helper.php'), 'utf8')).replace(/^<\?php\s*/, '') + '\n}\n';
await writeFile(path.join(root, 'freessl.php'), php);
console.log(JSON.stringify({ output: destination, bytes: Buffer.byteLength(page), inline_script_sha256: hash }));

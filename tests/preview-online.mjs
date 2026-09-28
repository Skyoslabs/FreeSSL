import http from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MockCA } from './mock-ca.mjs';
import { phpFixture } from './php-runtime.mjs';
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const ca = await new MockCA().init();
const base = '/tools/freessl', installDirectory = '/site' + base;
const fixture = await phpFixture({ installDirectory, transport: async (url, options) => {
  // Only this isolated preview slows finalization so the visible progress can be reviewed.
  if (new URL(url).pathname.includes('/finalize/') && options.body) await new Promise(resolve => setTimeout(resolve, 8000));
  return ca.fetch(url, options);
} });
// Explicitly simulate a non-secure HTTP page without browser WebCrypto. The
// actual PHP/OpenSSL implementation handles all signing through a mock CA.
const bootstrap = `const testNativeFetch = globalThis.fetch.bind(globalThis);
document.addEventListener('DOMContentLoaded', () => document.getElementById('test-due').addEventListener('click', async () => { await testNativeFetch('/test-due', { method: 'POST' }); location.reload(); }));
Object.defineProperty(globalThis, 'isSecureContext', { value: false });\nObject.defineProperty(crypto, 'subtle', { value: undefined });\n`;
const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  if (url.pathname === '/test-setup' && request.method === 'POST') {
    const password = randomBytes(18).toString('base64url');
    const result = await fixture.request('set-password', { password, confirmPassword: password }, { server: { HTTPS: 'off', HTTP_ORIGIN: 'http://site.test' } });
    if (result.status === 200) await writeFile('/private/tmp/freessl-browser-password.txt', password, { mode: 0o600 });
    response.writeHead(result.status); response.end('Isolated test login prepared'); return;
  }
  if (url.pathname === '/test-due' && request.method === 'POST') {
    const saved = JSON.parse(fixture.php.readFileAsText(installDirectory + '/ssl-helper.config.php').slice(fixture.guard.length));
    for (const record of Object.values(saved.records || {})) record.renewAt = Math.floor(Date.now() / 1000) - 1;
    fixture.php.writeFile(installDirectory + '/ssl-helper.config.php', fixture.guard + JSON.stringify(saved));
    response.writeHead(200); response.end('Simulated renewal window'); return;
  }
  if (url.pathname === base + '/freessl.php') {
    try {
      let body = ''; for await (const part of request) { body += part; if (body.length > 32768) throw new Error(); }
      const result = await fixture.request(url.searchParams.get('action'), body ? JSON.parse(body) : null, {
        headers: { Cookie: request.headers.cookie || '' },
        server: { HTTPS: 'off', HTTP_HOST: request.headers.host, HTTP_ORIGIN: request.headers.origin || '', HTTP_SEC_FETCH_SITE: request.headers['sec-fetch-site'] || '' }
      });
      response.writeHead(result.status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
        ...(result.headers['set-cookie'] ? { 'Set-Cookie': result.headers['set-cookie'] } : {}) }); response.end(result.raw);
    } catch { response.writeHead(500); response.end(); }
    return;
  }
  if (url.pathname === base + '/readme.md') {
    response.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' }); response.end(await readFile(path.join(root, 'readme.md'))); return;
  }
  if (url.pathname !== base + '/freessl.html') { response.writeHead(404); response.end(); return; }
  let html = await readFile(path.join(root, 'freessl.html'), 'utf8');
  const originalScript = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const script = bootstrap + originalScript;
  const hash = createHash('sha256').update(script).digest('base64');
  html = html.replace(originalScript, () => script).replace(/script-src 'sha256-[^']+'/g, "script-src 'sha256-" + hash + "'")
    .replace('<title>', '<title>HTTP 模拟验收 / ')
    .replace('我已阅读并同意 <a id="terms-link"', '本页使用真实 PHP、模拟证书服务，不提交真实申请。我已了解 <a id="terms-link"')
    .replace('Let’s Encrypt 服务条款</a>', '模拟验收说明</a>')
    .replace('模拟验收说明</a>。', '模拟验收说明</a>。测试只在本机运行，结果不可用于网站。');
  html = html.replace('<main>', '<main><div class="notice"><strong>隔离模拟验收</strong><p>浏览器 WebCrypto 已禁用，所有签发只在本机模拟。</p><button id="test-due" class="secondary">模拟进入续期时间</button></div>');
  response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); response.end(html);
});
server.listen(0, '127.0.0.1', () => console.log('HTTP PHP browser test: http://127.0.0.1:' + server.address().port + base + '/freessl.html'));

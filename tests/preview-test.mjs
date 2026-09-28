import http from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { build } from 'esbuild';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MockCA } from './mock-ca.mjs';
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const ca = await new MockCA().init();
const password = randomBytes(18).toString('base64url');
await writeFile('/private/tmp/freessl-local-browser-password.txt', password, { mode: 0o600 });
const seed = await build({ stdin: { contents: "import {localReady,localStatus,setLocalPassword} from './src/local.js'; window.sslTestReady=(async()=>{await localReady();if(!localStatus().configured)await setLocalPassword(" + JSON.stringify(password) + ',' + JSON.stringify(password) + ");})();", resolveDir: root }, bundle: true, write: false, format: 'iife', platform: 'browser' });
const bootstrap = `{
  const nativeFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (url, options = {}) => {
    const { signal, ...forward } = options;
    return nativeFetch('/mock-api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: String(url), options: forward }), signal });
  };
}\n`;
const server = http.createServer(async (request, response) => {
  if (request.url === '/mock-api' && request.method === 'POST') {
    try {
      let data = ''; for await (const part of request) { data += part; if (data.length > 100000) throw new Error('Request too large'); }
      const input = JSON.parse(data); const result = await ca.fetch(input.url, input.options);
      response.writeHead(result.status, Object.fromEntries(result.headers)); response.end(await result.text());
    } catch { response.writeHead(500, { 'Content-Type': 'application/json' }); response.end(JSON.stringify({ detail: 'Isolated mock CA test failed' })); }
    return;
  }
  if (request.url !== '/') { response.writeHead(404); response.end(); return; }
  let html = await readFile(path.join(root, 'freessl.html'), 'utf8');
  const originalScript = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const script = bootstrap + seed.outputFiles[0].text + '\nwindow.sslTestReady.then(()=>{' + originalScript + '});';
  const hash = createHash('sha256').update(script).digest('base64');
  html = html.replace(originalScript, () => script).replace(/script-src 'sha256-[^']+'/g, "script-src 'sha256-" + hash + "'")
    .replace('connect-src https:', "connect-src 'self' https:")
    .replace('<title>', '<title>模拟验收 / ')
    .replace('申请免费 SSL 证书</h1>', '模拟验收 · 不向 CA 申请</h1>')
    .replace('我已阅读并同意 <a id="terms-link"', '本页只用于本地模拟测试，不提交任何真实证书申请。我已了解 <a id="terms-link"')
    .replace('Let’s Encrypt 服务条款</a>', '模拟验收说明</a>')
    .replace('。申请的域名和公钥会发送给官方服务，私钥不会发送。', '。本页所有请求均由本机模拟服务处理，签发结果不可用于真实网站。');
  html = html.replace('<main>', '<main><div class="notice"><strong>本机隔离模拟验收</strong><p>所有签发请求由本机模拟 CA 处理，页面操作不会申请公网证书。</p></div>');
  response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); response.end(html);
});
server.listen(0, '127.0.0.1', () => console.log('Mock browser test: http://127.0.0.1:' + server.address().port + '/'));

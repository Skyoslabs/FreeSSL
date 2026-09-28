import { test } from 'node:test';
import assert from 'node:assert/strict';
import { phpFixture } from './php-runtime.mjs';
import { MockCA } from './mock-ca.mjs';
import { build } from 'esbuild';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const file = { name: 'test-validation-token-123456', content: 'test-validation-token-123456.' + 'b'.repeat(43) };
test('Real PHP: unconfigured and unauthorized requests cannot create files', async t => {
  const { php, configure, request } = await phpFixture(); t.after(() => php.exit());
  assert.equal((await request('status')).body.configured, false);
  assert.equal((await request('write', [file])).status, 503);
  assert.equal(php.fileExists('/site/.well-known'), false);
  configure(); assert.equal((await request('status')).body.configured, true);
  assert.equal((await request('write', [file], { headers: { Cookie: 'ssl_assistant_session=wrong' } })).status, 403);
  assert.equal((await request('write', [file], { server: { HTTP_SEC_FETCH_SITE: 'cross-site' } })).status, 403);
  assert.equal((await request('write', [file], { server: { HTTP_ORIGIN: 'https://evil.test' } })).status, 403);
  assert.equal(php.fileExists('/site/.well-known'), false);
  php.exit();
});
test('Online adapter supports HTTP and HTTPS without WebCrypto and sends only public challenge data', async t => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), options });
    return new Response(String(url).includes('freessl.php') ? JSON.stringify({ helper: 'freessl', version: 2, ok: true }) : file.content);
  };
  const adapter = await import('../src/online.js');
  const context = adapter.onlineContext(new URL('http://site.test/SSL.html'));
  assert.equal(adapter.onlineContext(new URL('file:///desktop/SSL.html')).online, false);
  assert.equal(context.online, true);
  assert.equal(adapter.onlineContext(new URL('https://site.test/SSL.html')).online, true);
  const nested = adapter.onlineContext(new URL('https://site.test/tools/freessl.html'));
  assert.equal(nested.helper, 'https://site.test/tools/freessl.php');
  assert.equal(await adapter.placeOnline(context, [{ ...file, privateKey: 'MUST_NOT_TRANSMIT', csr: 'MUST_NOT_TRANSMIT' }]), 1);
  assert.deepEqual(JSON.parse(calls[0].options.body), { files: [file] });
  assert.equal(calls[0].options.credentials, 'same-origin');
  assert.equal(calls[1].url, 'http://site.test/.well-known/acme-challenge/' + file.name);
  assert.equal(await adapter.placeOnline(nested, [file]), 1);
  assert.equal(calls[2].url, 'https://site.test/tools/freessl.php?action=write');
  assert.equal(calls[3].url, 'https://site.test/.well-known/acme-challenge/' + file.name);
});
test('Real PHP: writes exact extensionless challenge content; retry is idempotent; other contents remain intact', async t => {
  const { php, configure, request } = await phpFixture(); t.after(() => php.exit()); configure();
  const result = await request('write', [file]);
  assert.equal(result.status, 200, result.raw + result.errors); assert.equal(result.body.written, 1);
  assert.equal(php.readFileAsText('/site/.well-known/acme-challenge/' + file.name), file.content);
  assert.equal((await request('write', [file])).status, 200);
  assert.equal((await request('write', [{ ...file, content: file.name + '.' + 'c'.repeat(43) }])).status, 409);
  assert.equal(php.readFileAsText('/site/.well-known/acme-challenge/' + file.name), file.content);
  php.exit();
});
test('Real PHP: rejects path traversal, extra fields, script/PEM content and requests above bounds before creating directories', async t => {
  const { php, configure, request } = await phpFixture(); t.after(() => php.exit()); configure();
  for (const files of [
    [{ name: '../../index.php', content: file.content }],
    [{ ...file, path: 'index.php' }], [{ ...file, content: '<?php phpinfo(); ?>' }],
    [{ ...file, content: '-----BEGIN PRIVATE KEY-----' }], [], Array(101).fill(file)
  ]) assert.equal((await request('write', files)).status, 400);
  assert.equal((await request('write', [{ ...file, content: 'x'.repeat(33000) }])).status, 413);
  assert.equal(php.fileExists('/site/.well-known'), false);
  php.exit();
});
test('Real PHP: refuses symbolic-link directories and files, and refuses deployment outside the web root', async t => {
  const { php, configure, request } = await phpFixture(); t.after(() => php.exit()); configure();
  php.mkdir('/outside'); php.writeFile('/outside/keep', 'untouched');
  await php.runStream({ code: '<?php symlink("/outside", "/site/.well-known");' }).then(result => result.finished);
  assert.equal((await request('write', [file])).status, 409);
  php.unlink('/site/.well-known'); php.mkdir('/site/.well-known'); php.mkdir('/site/.well-known/acme-challenge');
  await php.runStream({ code: `<?php symlink('/outside/keep', '/site/.well-known/acme-challenge/${file.name}');` }).then(result => result.finished);
  assert.equal((await request('write', [file])).status, 409);
  assert.equal(php.readFileAsText('/outside/keep'), 'untouched');
  assert.equal((await request('write', [file], { server: { DOCUMENT_ROOT: '/outside' } })).status, 409);
  php.exit();
});
test('Integrated online chain: actual ACME signatures, real PHP placement, public route verification and matching certificate', async t => {
  const ca = await new MockCA().init();
  const fixture = await phpFixture(); fixture.configure(); t.after(() => fixture.php.exit());
  const originalFetch = globalThis.fetch; t.after(() => { globalThis.fetch = originalFetch; });
  globalThis.fetch = async (url, options = {}) => {
    const parsed = new URL(String(url));
    if (parsed.hostname === 'acme-v02.api.letsencrypt.org') return ca.fetch(String(url), options);
    assert.equal(parsed.origin, 'https://site.test');
    if (parsed.pathname === '/freessl.php') {
      const result = await fixture.request(parsed.searchParams.get('action'), options.body ? JSON.parse(options.body).files : null);
      return new Response(result.raw, { status: result.status, headers: { 'Content-Type': 'application/json' } });
    }
    assert.match(parsed.pathname, /^\/\.well-known\/acme-challenge\/[A-Za-z0-9_-]+$/);
    return new Response(fixture.php.readFileAsText('/site' + parsed.pathname));
  };
  const adapter = await import('../src/online.js?integrated');
  const folder = await mkdtemp(path.join(tmpdir(), 'ssl-online-chain-'));
  const compiled = path.join(folder, 'core.mjs');
  await build({ entryPoints: [fileURLToPath(new URL('../src/core.js', import.meta.url))], outfile: compiled, bundle: true, platform: 'node', format: 'esm', target: 'node24', logLevel: 'silent' });
  const core = await import(pathToFileURL(compiled)); core.installNetworkGuard();
  const context = adapter.onlineContext(new URL('https://site.test/SSL.html'));
  assert.equal((await adapter.probeOnline(context)).configured, true);
  const client = await core.connect('production');
  const session = await core.createSession({ client, environment: 'production', domains: ['example.com', 'www.example.com'], method: 'http-01' });
  const resources = await core.challengeResources(session);
  assert.equal(await adapter.placeOnline(context, resources), 2);
  for (const resource of resources) assert.equal(fixture.php.readFileAsText('/site/.well-known/acme-challenge/' + resource.name), resource.content);
  const result = await core.issueCertificate(session);
  assert.equal(result.certificate.match(/BEGIN CERTIFICATE/g).length, 2);
  assert.ok(result.validity.notAfter > new Date()); assert.ok(ca.signatureCount > 5);
});

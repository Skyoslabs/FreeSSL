import { MockCA } from './mock-ca.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { mkdtemp, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { zipSync, strToU8, unzipSync } from 'fflate';
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const temporary = await mkdtemp(path.join(tmpdir(), 'freessl-tests-'));
const compiled = path.join(temporary, 'core.mjs');
await build({ absWorkingDir: root, entryPoints: ['src/core.js'], outfile: compiled, bundle: true, platform: 'node', format: 'esm', target: 'node24', logLevel: 'silent' });
const core = await import(pathToFileURL(compiled));
const originalFetch = globalThis.fetch;

async function fixture(options = {}) {
  const ca = Object.assign(await new MockCA().init(), options); globalThis.fetch = ca.fetch;
  const client = await core.connect('production');
  const session = await core.createSession({ client, environment: 'production', domains: ['example.com', 'www.example.com'], method: 'http-01', ...options });
  return { ca, client, session };
}

test('Normalize multiple domains, international names and wildcard DNS; reject URLs, IPs and injection', () => {
  assert.deepEqual(core.normalizeDomains('EXAMPLE.COM\nwww.example.com,example.com'), ['example.com', 'www.example.com']);
  assert.equal(core.normalizeDomain('例子.中国', 'dns-01'), 'xn--fsqu00a.xn--fiqs8s');
  assert.equal(core.normalizeDomain('*.example.com', 'dns-01'), '*.example.com');
  for (const value of ['https://example.com', '127.0.0.1', 'a.example.com/path', '-invalid.com', 'example.com@evil.test', '<script>.com', 'localhost']) assert.throws(() => core.normalizeDomain(value));
  assert.throws(() => core.normalizeDomains(''));
  assert.throws(() => core.normalizeDomain('*.example.com', 'http-01'));
});
test('HTTP multi-domain issuance signs real JWS and produces matching RSA key, SANs, valid leaf and full chain', async () => {
  const { ca, session } = await fixture();
  const resources = await core.challengeResources(session);
  assert.equal(resources.length, 2); assert.equal(resources[0].url, 'http://example.com/.well-known/acme-challenge/' + resources[0].name);
  assert.ok(resources[0].content.startsWith(resources[0].name + '.'));
  const result = await core.issueCertificate(session);
  assert.match(result.privateKey, /BEGIN PRIVATE KEY/); assert.equal(result.certificate.match(/BEGIN CERTIFICATE/g).length, 2);
  assert.ok(result.validity.notAfter > new Date()); assert.ok(ca.signatureCount > 5); assert.equal(ca.finalizeCount, 1);
});
test('DNS wildcard plus apex preserves two TXT values at the same hostname, and signs ECDSA CSR', async () => {
  const { session } = await fixture({ domains: ['*.example.com', 'example.com'], method: 'dns-01', keyAlgorithm: 'ec-p256' });
  const resources = await core.challengeResources(session);
  assert.equal(resources[0].name, '_acme-challenge.example.com.'); assert.equal(resources[1].name, resources[0].name);
  assert.notEqual(resources[0].content, resources[1].content);
  const result = await core.issueCertificate(session); assert.match(result.certificate, /BEGIN CERTIFICATE/);
});
test('Bad nonce is retried with a new signed request, without duplicate accounts', async () => {
  const { ca, session } = await fixture({ badNonceOnce: true });
  assert.equal(ca.accounts.size, 1); assert.match((await core.issueCertificate(session)).certificate, /BEGIN CERTIFICATE/);
});
test('A lost finalization response can resume without regenerating or mismatching the private key', async () => {
  const { ca, session } = await fixture({ dropFinalizeOnce: true }); const originalKey = session.privateKey;
  await assert.rejects(core.issueCertificate(session), /disconnect/);
  const result = await core.issueCertificate(session); assert.equal(result.privateKey, originalKey); assert.equal(ca.finalizeCount, 1);
});
test('Authorization reuse skips validation files; renewed certificate remains matched to its new key', async () => {
  const { session } = await fixture({ cachedAuthorization: true });
  assert.deepEqual(await core.challengeResources(session), []); assert.match((await core.issueCertificate(session)).certificate, /BEGIN CERTIFICATE/);
});
test('Invalid verification reports actual CA detail and signals that a new order is required', async () => {
  const { session } = await fixture({ invalidChallenge: true });
  await assert.rejects(core.issueCertificate(session), error => error.invalidOrder && error.message.includes('NXDOMAIN'));
});
test('A certificate for another private key is refused before being offered for download', async () => {
  const first = await fixture(); const firstCsr = first.session.csr;
  const { ca, session } = await fixture(); ca.overrideCsr = firstCsr;
  await assert.rejects(core.issueCertificate(session), /私钥不匹配/); assert.equal(session.certificate, null);
});
test('Challenge ZIP contains the exact extensionless token file at the correct nested path, with no private key', () => {
  const name = '.well-known/acme-challenge/token-example'; const content = 'token-example.public-thumbprint';
  const zip = zipSync({ [name]: strToU8(content) }, { level: 0 }); const files = unzipSync(zip);
  assert.deepEqual(Object.keys(files), [name]); assert.equal(new TextDecoder().decode(files[name]), content);
  assert.ok(!Object.keys(files).some(name => /key|pem/.test(name)));
});
test('Network guard prevents directory redirects from sending signed requests to non-official hosts', async () => {
  globalThis.fetch = async () => new Response('{}'); core.installNetworkGuard();
  await assert.rejects(core.connect('staging'), /正式证书/);
  assert.throws(() => fetch('https://untrusted.example/collect'), /非官方/);
  assert.throws(() => fetch('https://acme-staging-v02.api.letsencrypt.org/directory'), /非官方/);
  assert.throws(() => fetch('http://acme-v02.api.letsencrypt.org/directory'), /非官方/);
  assert.equal((await fetch(core.DIRECTORIES.production)).status, 200);
  globalThis.fetch = originalFetch;
});

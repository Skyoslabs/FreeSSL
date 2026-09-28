import { mkdtemp, writeFile, readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
const base = 'https://acme-v02.api.letsencrypt.org';
const decode = value => JSON.parse(Buffer.from(value, 'base64url').toString());
// Isolated mock CA: verify actual WebCrypto JWS signatures, verify each actual
// CSR with OpenSSL, and sign a real local X.509 leaf with a throwaway test CA.
// Nothing in these tests registers accounts or issues public certificates.
export class MockCA {
  accounts = new Map(); orders = new Map(); sequence = 0; nonce = 0;
  badNonceOnce = false; cachedAuthorization = false; invalidChallenge = false;
  dropFinalizeOnce = false; overrideCsr = null; finalizeCount = 0; signatureCount = 0;
  async init() {
    this.folder = await mkdtemp(path.join(tmpdir(), 'ssl-mock-ca-'));
    await exec('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-subj', '/CN=Isolated Test CA', '-days', '3'], { cwd: this.folder });
    return this;
  }
  response(body, status = 200, headers = {}) {
    return new Response(body == null ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Replay-Nonce': 'nonce-' + (++this.nonce), ...headers } });
  }
  status(order) {
    if (order.invalid) return 'invalid';
    if (order.certificate) return 'valid';
    return order.auths.every(auth => auth.valid) ? 'ready' : 'pending';
  }
  snapshot(order) { return { status: this.status(order), identifiers: order.domains.map(value => ({ type: 'dns', value })), authorizations: order.auths.map(auth => auth.url), finalize: base + '/finalize/' + order.id, certificate: order.certificate ? base + '/cert/' + order.id : undefined }; }
  authSnapshot(auth) {
    const wildcard = auth.domain.startsWith('*.');
    return { identifier: { type: 'dns', value: auth.domain.replace(/^\*\./, '') }, wildcard, status: auth.invalid ? 'invalid' : auth.valid ? 'valid' : 'pending',
      challenges: (wildcard ? ['dns-01'] : ['http-01', 'dns-01']).map(type => ({ type, token: auth.token, url: auth.url + '/' + type, status: auth.invalid ? 'invalid' : auth.valid ? 'valid' : 'pending',
        ...(auth.invalid ? { error: { type: 'urn:ietf:params:acme:error:dns', detail: 'NXDOMAIN in isolated test' } } : {}) })) };
  }
  fetch = async (url, options = {}) => {
    const pathname = new URL(url).pathname;
    if (pathname === '/directory') return this.response({ newNonce: base + '/new-nonce', newAccount: base + '/new-account', newOrder: base + '/new-order', meta: { termsOfService: 'https://letsencrypt.org/documents/test-terms.pdf' } });
    if (pathname === '/new-nonce') return this.response(null);
    assert.equal(options.method, 'POST');
    const jws = JSON.parse(options.body); const header = decode(jws.protected); const payload = jws.payload ? decode(jws.payload) : null;
    assert.equal(header.url, url); assert.ok(header.nonce);
    const jwk = header.jwk || this.accounts.get(header.kid);
    const algorithm = jwk.kty === 'RSA' ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } : { name: 'ECDSA', namedCurve: 'P-256' };
    const key = await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['verify']);
    assert.equal(header.alg, jwk.kty === 'RSA' ? 'RS256' : 'ES256');
    assert.ok(await crypto.subtle.verify(jwk.kty === 'RSA' ? algorithm : { name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(jws.signature, 'base64url'), new TextEncoder().encode(jws.protected + '.' + jws.payload)), 'ACME JWS signature must verify independently');
    this.signatureCount++;
    if (this.badNonceOnce) { this.badNonceOnce = false; return this.response({ type: 'urn:ietf:params:acme:error:badNonce', detail: 'Retry with a new nonce' }, 400); }
    if (pathname === '/new-account') {
      const existing = [...this.accounts.entries()].find(([, value]) => JSON.stringify(value) === JSON.stringify(jwk));
      const id = existing?.[0] || base + '/account/' + this.accounts.size;
      if (payload.onlyReturnExisting) {
        assert.ok(existing, 'Account must already exist');
        return this.response({ status: 'valid' }, 200, { Location: id });
      }
      assert.equal(payload.termsOfServiceAgreed, true); assert.deepEqual(payload.contact, []);
      this.accounts.set(id, jwk); return this.response({ status: 'valid' }, 201, { Location: id });
    }
    if (pathname === '/new-order') {
      const id = ++this.sequence; const domains = payload.identifiers.map(item => item.value);
      const order = { id, domains, auths: domains.map((domain, index) => ({ domain, url: base + '/auth/' + id + '/' + index, token: 'validation-token-for-' + id + '-domain-' + index, valid: this.cachedAuthorization })) };
      this.orders.set(id, order); return this.response(this.snapshot(order), 201, { Location: base + '/order/' + id });
    }
    const parts = pathname.split('/'); const order = this.orders.get(Number(parts[2]));
    if (parts[1] === 'order') return this.response(this.snapshot(order));
    if (parts[1] === 'auth') {
      const auth = order.auths[Number(parts[3])];
      if (parts[4]) {
        if (payload) {
          assert.deepEqual(payload, {});
          if (this.invalidChallenge) { auth.invalid = true; order.invalid = true; } else auth.valid = true;
        }
        return this.response(this.authSnapshot(auth).challenges.find(challenge => challenge.type === parts[4]));
      }
      return this.response(this.authSnapshot(auth));
    }
    if (parts[1] === 'finalize') {
      this.finalizeCount++;
      const csr = Buffer.from(this.overrideCsr || payload.csr, 'base64url');
      await writeFile(path.join(this.folder, 'request.der'), csr);
      await exec('openssl', ['req', '-inform', 'DER', '-in', 'request.der', '-verify', '-noout'], { cwd: this.folder });
      await exec('openssl', ['req', '-inform', 'DER', '-in', 'request.der', '-outform', 'PEM', '-out', 'request.pem'], { cwd: this.folder });
      await writeFile(path.join(this.folder, 'extensions.conf'), 'subjectAltName=' + order.domains.map(domain => 'DNS:' + domain).join(',') + '\n');
      await exec('openssl', ['x509', '-req', '-in', 'request.pem', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '2', '-extfile', 'extensions.conf', '-out', 'leaf.pem'], { cwd: this.folder });
      order.certificate = await readFile(path.join(this.folder, 'leaf.pem'), 'utf8') + await readFile(path.join(this.folder, 'ca.pem'), 'utf8');
      if (this.dropFinalizeOnce) { this.dropFinalizeOnce = false; throw new TypeError('Simulated network disconnect after server accepted the CSR'); }
      return this.response(this.snapshot(order));
    }
    if (parts[1] === 'cert') return new Response(order.certificate, { headers: { 'Content-Type': 'application/pem-certificate-chain', 'Replay-Nonce': 'nonce-' + (++this.nonce) } });
    throw new Error('Unexpected test path: ' + pathname);
  };
}

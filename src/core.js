import { AcmeClient } from '../vendor/fishball-acme/src/AcmeClient.ts';
import { generateKeyPair } from '../vendor/fishball-acme/src/utils/crypto.ts';
import { generateCSR } from '../vendor/fishball-acme/src/utils/generateCSR.ts';
import { encodeBase64Url } from '../vendor/fishball-acme/src/utils/base64.ts';
import { exportKeyPairToPem } from '../vendor/fishball-acme/src/CryptoKeyUtils/exportKeyPairToPem.ts';
import { decodeValidity } from '../vendor/fishball-acme/src/CertUtils/decodeValidity.ts';
import { extractFirstPemObject } from '../vendor/fishball-acme/src/utils/pem.ts';
import { decodeSequence, decodeTagLengthValue } from '../vendor/fishball-acme/src/Asn1/Asn1DecodeHelpers.ts';

export const DIRECTORIES = Object.freeze({
  production: 'https://acme-v02.api.letsencrypt.org/directory'
});
const ALLOWED_HOSTS = new Set(Object.values(DIRECTORIES).map(url => new URL(url).hostname));

// ACME account keys and certificate keys stay in memory. Every network destination
// is an official Let's Encrypt HTTPS endpoint, including URLs returned by the CA.
export function installNetworkGuard() {
  const originalFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (url, options = {}) => {
    const parsed = new URL(typeof url === 'string' ? url : url.url || String(url));
    if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname) || parsed.port || parsed.username || parsed.password) {
      throw new Error('已阻止连接到非官方证书接口。');
    }
    return originalFetch(url, {
      ...options, credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store',
      signal: options.signal || AbortSignal.timeout(25000)
    });
  };
}

export function normalizeDomain(value, method = 'http-01') {
  const input = String(value).trim().toLowerCase().replace(/\.$/, '');
  const wildcard = input.startsWith('*.');
  const plain = wildcard ? input.slice(2) : input;
  if (!plain || /[\s\/:?#@\\]/.test(plain) || plain.includes('*')) throw new Error('请只填写域名，不要填写 https://、端口或路径。');
  let domain;
  try { domain = new URL('https://' + plain).hostname; } catch { throw new Error('域名格式不正确。'); }
  const labels = domain.split('.');
  if (domain.length > 253 || labels.length < 2 || /^\d+(\.\d+){3}$/.test(domain) ||
      labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error('请输入完整的有效域名，例如 example.com。');
  if (wildcard && method !== 'dns-01') throw new Error('泛域名（*.example.com）需要选择 DNS 验证。');
  return (wildcard ? '*.' : '') + domain;
}

export async function connect(environment = 'production') {
  if (environment !== 'production') throw new Error('仅支持正式证书签发。');
  const client = await AcmeClient.init(DIRECTORIES[environment]);
  const terms = client.directory.meta?.termsOfService;
  if (!terms || new URL(terms).protocol !== 'https:' || new URL(terms).hostname !== 'letsencrypt.org') throw new Error('无法读取官方服务条款，请稍后重试。');
  return client;
}

async function readJson(response) {
  const body = await response.json();
  if (!response.ok) {
    const error = new Error(body.detail || '证书接口暂时无法处理此操作。');
    error.type = body.type;
    error.retryAfter = response.headers.get('Retry-After');
    throw error;
  }
  return body;
}
export const readOrder = session => session.account.jwsFetch(session.order.url).then(readJson);

export function normalizeDomains(input, method = 'http-01') {
  const raw = Array.isArray(input) ? input : String(input).split(/[\s,，;；]+/);
  const domains = [...new Set(raw.filter(Boolean).map(domain => normalizeDomain(domain, method)))];
  if (!domains.length) throw new Error('请先填写至少一个域名。');
  return domains;
}

export async function createSession({ client, account, environment, domains: input, method, keyAlgorithm = 'rsa-2048' }) {
  if (environment !== 'production') throw new Error('仅支持正式证书签发。');
  const domains = normalizeDomains(input, method);
  const domain = domains[0];
  if (!['rsa-2048', 'ec-p256'].includes(keyAlgorithm)) throw new Error('密钥类型无效。');
  // Explicit consent is enforced by the UI before this function is called.
  account ||= await client.createAccount({ emails: [] });
  const keyPair = await generateKeyPair(keyAlgorithm);
  const csr = encodeBase64Url(await generateCSR({ domains, keyPair }));
  const privateKey = (await exportKeyPairToPem(keyPair)).privateKey + '\n';
  const order = await account.createOrder({ domains });
  return { client, account, environment, domain, domains, method, keyAlgorithm, keyPair, csr, privateKey, order, certificate: null };
}

export async function challengeResources(session, method = session.method) {
  if (!['http-01', 'dns-01'].includes(method)) throw new Error('验证方式无效。');
  session.method = method;
  const resources = [];
  for (const authorization of session.order.authorizations) {
    const snapshot = await readJson(await session.account.jwsFetch(authorization.url));
    if (snapshot.status === 'valid') continue;
    if (['invalid', 'expired', 'revoked', 'deactivated'].includes(snapshot.status)) {
      const error = new Error(snapshot.challenges?.find(item => item.error)?.error?.detail || '本次验证已失效，请重新生成验证文件。');
      error.invalidOrder = true; throw error;
    }
    const challenge = authorization.findChallenge(method);
    if (!challenge) throw new Error('证书服务没有提供所选验证方式。');
    const resource = method === 'http-01' ? await challenge.getHttpResource() : await challenge.getDnsRecordAnswer();
    if (method === 'http-01' && !/^[A-Za-z0-9_-]{16,128}$/.test(resource.name)) throw new Error('验证文件名不符合预期。');
    resources.push({ domain: authorization.domain, challenge, authorization, ...resource });
  }
  return resources;
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitForOrder(session, predicate, onStatus) {
  const deadline = Date.now() + 240000;
  while (Date.now() < deadline) {
    const snapshot = await readOrder(session);
    if (snapshot.status === 'invalid') {
      for (const authorization of session.order.authorizations) {
        const auth = await readJson(await session.account.jwsFetch(authorization.url));
        const detail = auth.challenges?.find(item => item.error)?.error;
        if (detail) { const error = new Error(detail.detail || '域名验证未通过。'); error.type = detail.type; error.invalidOrder = true; throw error; }
      }
      const error = new Error(snapshot.error?.detail || '本次验证已失效，请重新生成验证文件。');
      error.invalidOrder = true; throw error;
    }
    if (predicate(snapshot)) return snapshot;
    onStatus?.(snapshot.status);
    await sleep(2000);
  }
  throw new Error('证书服务仍在处理。请保留这个页面，稍后再次点击“提交验证并取得证书”；无需重新申请。');
}

export async function issueCertificate(session, { submit = true, onStatus } = {}) {
  let snapshot = await readOrder(session);
  if (snapshot.status === 'pending' && submit) {
    const resources = await challengeResources(session);
    for (const resource of resources) {
      const challengeState = await readJson(await session.account.jwsFetch(resource.challenge.url));
      if (challengeState.status === 'pending') {
        await readJson(await session.account.jwsFetch(resource.challenge.url, { payload: {} }));
      }
    }
  }
  snapshot = await waitForOrder(session, order => ['ready', 'processing', 'valid'].includes(order.status), onStatus);
  if (snapshot.status === 'ready') {
    // Generate and retain ONE key and CSR before finalization. An interrupted
    // request is safely retried with the same CSR, never a mismatching new key.
    onStatus?.('finalizing');
    await readJson(await session.account.jwsFetch(snapshot.finalize, { payload: { csr: session.csr } }));
  }
  snapshot = await waitForOrder(session, order => order.status === 'valid', onStatus);
  if (!snapshot.certificate) throw new Error('服务尚未返回证书下载地址，请稍后继续。');
  const response = await session.account.jwsFetch(snapshot.certificate);
  if (!response.ok) await readJson(response);
  const certificate = await response.text();
  if (certificate.length > 256000 || !certificate.includes('-----BEGIN CERTIFICATE-----')) throw new Error('返回的证书格式无效，请稍后继续下载。');
  const leaf = extractFirstPemObject(certificate);
  const [tbs] = decodeSequence(leaf);
  const fields = decodeSequence(tbs);
  const offset = fields[0]?.[0] === 0xa0 ? 1 : 0;
  const certSpki = fields[offset + 5];
  const expectedSpki = new Uint8Array(await crypto.subtle.exportKey('spki', session.keyPair.publicKey));
  if (!certSpki || certSpki.length !== expectedSpki.length || certSpki.some((byte, i) => byte !== expectedSpki[i])) throw new Error('证书与本次私钥不匹配，已停止下载。');
  const extensionWrapper = fields.find(field => field[0] === 0xa3);
  const extensions = extensionWrapper ? decodeSequence(decodeTagLengthValue(extensionWrapper)[2]) : [];
  // DER OID 2.5.29.17 (subjectAltName).
  const san = extensions.map(extension => decodeSequence(extension)).find(parts =>
    parts[0]?.length === 5 && Array.from(parts[0]).join(',') === '6,3,85,29,17');
  const sanValue = san?.[san.length - 1];
  const dnsNames = sanValue ? decodeSequence(decodeTagLengthValue(sanValue)[2])
    .filter(field => field[0] === 0x82).map(field => new TextDecoder().decode(decodeTagLengthValue(field)[2])) : [];
  if (!session.domains.every(domain => dnsNames.includes(domain))) throw new Error('返回的证书未包含本次域名，已停止下载。');
  session.certificate = certificate;
  session.validity = decodeValidity(certificate);
  return { certificate, privateKey: session.privateKey, validity: session.validity };
}

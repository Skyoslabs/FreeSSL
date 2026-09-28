// Native browser storage for the standalone HTML. Nothing is sent to a server.
// The password unlocks an AES-GCM vault containing certificate records and keys.
const encoder = new TextEncoder(), decoder = new TextDecoder();
let key = null, state = null, saved = null, database = null;
const storageKey = globalThis.location?.pathname || 'standalone';
const aad = encoder.encode('ssl-assistant-vault-v1');
export async function localReady() {
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle || !globalThis.indexedDB) return false;
  if (!database) database = await new Promise((resolve, reject) => {
    const request = indexedDB.open('ssl-assistant-v1', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('vault');
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(new Error('浏览器无法保存申请记录，请使用普通 Chrome 窗口打开。'));
  });
  saved = await new Promise((resolve, reject) => {
    const request = database.transaction('vault').objectStore('vault').get(storageKey);
    request.onsuccess = () => resolve(request.result || null); request.onerror = () => reject(new Error('无法读取本地证书记录。'));
  });
  return true;
}
export function localStatus() { return { configured: !!saved, authenticated: !!state, records: state?.records || [], agreedTerms: state?.agreedTerms || {} }; }
function validatePassword(password, confirmation) {
  if (typeof password !== 'string' || [...password].length < 8 || password.includes('\0')) throw new Error('密码至少需要 8 个字符。');
  if (encoder.encode(password).length > 72) throw new Error('密码太长，请缩短后重试。');
  if (password !== confirmation) throw new Error('两次输入的密码不一致。');
}
async function derive(password, salt) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function persist() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, encoder.encode(JSON.stringify(state)));
  const next = { version: 1, salt: saved.salt, iv, data };
  await new Promise((resolve, reject) => {
    const transaction = database.transaction('vault', 'readwrite'); transaction.objectStore('vault').put(next, storageKey);
    transaction.oncomplete = resolve; transaction.onerror = () => reject(new Error('证书记录未保存，请下载证书包并检查浏览器存储权限。'));
    transaction.onabort = () => reject(new Error('证书记录未保存，请下载证书包并检查浏览器存储权限。'));
  });
  saved = next;
}
export async function setLocalPassword(password, confirmation) {
  validatePassword(password, confirmation);
  await localReady(); if (saved) throw new Error('密码已经设置，请直接登录。');
  saved = { salt: crypto.getRandomValues(new Uint8Array(16)) };
  key = await derive(password, saved.salt); state = { records: [], agreedTerms: {} };
  try { await persist(); } catch (error) { saved = null; state = null; key = null; throw error; }
}
export async function loginLocal(password) {
  await localReady(); if (!saved) throw new Error('首次使用，请先设置密码。');
  try {
    const candidate = await derive(password, saved.salt);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: saved.iv, additionalData: aad }, candidate, saved.data);
    const loaded = JSON.parse(decoder.decode(plaintext));
    if (!Array.isArray(loaded.records)) throw new Error();
    key = candidate; state = loaded;
  } catch { throw new Error('密码不正确，请重试。'); }
}
export function logoutLocal() { state = null; key = null; }
export async function saveLocalCertificate(session, termsUrl) {
  if (!state || !key) throw new Error('请先登录再保存证书。');
  const id = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode([session.environment, session.keyAlgorithm, ...[...session.domains].sort()].join('|')))), byte => byte.toString(16).padStart(2, '0')).join('');
  const notBefore = Math.floor(session.validity.notBefore.getTime() / 1000), notAfter = Math.floor(session.validity.notAfter.getTime() / 1000);
  const record = { id, domains: session.domains, environment: session.environment, keyAlgorithm: session.keyAlgorithm, method: session.method,
    target: session.target || 'other', notBefore, notAfter, renewAt: Math.floor(notBefore + (notAfter - notBefore) * 2 / 3), certificate: session.certificate, privateKey: session.privateKey };
  state.records = [...state.records.filter(item => item.id !== id), record]; state.agreedTerms[session.environment] = termsUrl;
  await persist(); return record;
}

import { connect, createSession, challengeResources, issueCertificate, normalizeDomains, readOrder, installNetworkGuard } from './core.js';
import { zipSync, strToU8 } from 'fflate';
import { onlineContext, probeOnline, placeOnline, onlineRequest } from './online.js';
import { localReady, localStatus, setLocalPassword, loginLocal, logoutLocal, saveLocalCertificate } from './local.js';

installNetworkGuard();
const $ = id => document.getElementById(id);
const ENVIRONMENT = 'production';
let client = null, session = null, cachedAccount = null, resources = [], busy = false, invalid = false;
let connectedEnvironment = null, termsUrl = null;
const online = onlineContext(window.location);
let helperStatus = null, detecting = true, localAvailable = false, view = 'apply';
const date = value => value.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' });

function announce(text) { $('activity-text').textContent = text; if (busy) $('operation-message').textContent = text; }
function step(number) {
  document.querySelectorAll('[data-step]').forEach(item => {
    const n = Number(item.dataset.step);
    item.classList.toggle('active', n === number); item.classList.toggle('done', n < number);
    if (n === number) item.setAttribute('aria-current', 'step'); else item.removeAttribute('aria-current');
  });
}
function setBusy(value) {
  busy = value;
  $('application').setAttribute('aria-busy', String(value));
  $('operation-status').hidden = !value || $('application').hidden;
  document.querySelectorAll('button[data-network]').forEach(button => button.disabled = value);
  $('start').disabled = value || detecting || !client || !$('terms').checked || !!session;
  $('issue').disabled = value || !session || invalid || (resources.length > 0 && !$('confirmed').checked);
  $('auto-place').disabled = value || invalid || !session || session.method !== 'http-01' || !resources.length || !helperStatus?.configured;
  ['setup-password', 'confirm-password', 'login-password'].forEach(id => $(id).disabled = value);
  ['domains', 'additional-domains', 'key-algorithm'].forEach(id => $(id).disabled = value || !!session);
  document.querySelectorAll('input[name=method],input[name=target]').forEach(input => input.disabled = value || !!session);
  if (!value && !session) configureTarget(false);
  $('activity').classList.toggle('working', value);
  $('saved-list').querySelectorAll('button').forEach(button => button.disabled = value);
}
function showView(next) {
  view = next; $('application').dataset.view = next;
  $('nav-apply').setAttribute('aria-current', next === 'apply' ? 'page' : 'false');
  $('nav-certificates').setAttribute('aria-current', next === 'certificates' ? 'page' : 'false');
  $('setup-card').hidden = next !== 'apply'; $('certificates-page').hidden = next !== 'certificates';
  $('challenge-card').hidden = next !== 'apply' || !session || !!session.certificate;
  $('result-card').hidden = next !== 'certificates' || !session?.certificate;
  $('reset-page').hidden = next !== 'apply' || !session;
  $('page-heading').textContent = next === 'certificates' ? '我的证书' : '申请 Let’s Encrypt 免费证书';
}
function updateLogin(status) {
  const required = !status.authenticated;
  $('auth-gate').hidden = !required; $('application').hidden = required; $('navigation').hidden = required;
  $('online-setup').hidden = status.configured; $('online-login').hidden = !status.configured;
  if (required) $('connection').textContent = '请先登录';
  $('auth-title').textContent = status.configured ? '登录 Free SSL' : '先设置登录密码';
  $('auth-description').textContent = status.configured ? '登录后就能查看证书、申请和续期。' : '以后用这个密码进入，可以让浏览器帮你记住。';
  $('password-help-php').hidden = !helperStatus?.capable;
  $('password-help-local').hidden = !!helperStatus?.capable;
  $('password-help').open = false;
}
async function checkOnline() {
  detecting = true; setBusy(busy); helperStatus = null;
  if (online.online) {
    try { helperStatus = await probeOnline(online); } catch { /* Standalone guide remains available. */ }
  }
  if (helperStatus?.capable) {
    updateLogin(helperStatus);
    $('runtime-label').textContent = 'PHP 模式';
    $('certificate-storage').textContent = '已自动保存到服务器';
  } else {
    try {
      localAvailable = await localReady();
      if (localAvailable) updateLogin(localStatus());
      else {
        $('auth-gate').hidden = false; $('application').hidden = true; $('navigation').hidden = true;
        $('online-setup').hidden = true; $('online-login').hidden = true;
        $('auth-title').textContent = '在电脑上继续办理';
        $('auth-description').textContent = '请在电脑上用 Chrome 打开安装包内的 freessl.html。详细步骤见 readme.md。';
      }
    } catch (error) { $('auth-error').hidden = false; $('auth-error').textContent = error.message; }
    $('runtime-label').textContent = '本地模式';
    $('certificate-storage').textContent = '已自动保存到当前浏览器';
  }
  configureTarget(!$('domains').value && !session); renderSavedRecords(); showView(view);
  detecting = false; setBusy(busy);
}
function configureTarget(fillDomain = true) {
  const target = document.querySelector('input[name=target]:checked').value;
  $('file-method-description').textContent = target === 'site' && helperStatus?.capable
    ? 'PHP 会自动放好验证文件，你不用上传。'
    : '将验证文件包上传到目标网站。';
  if (fillDomain && target === 'site' && online.online && !session) {
    try { $('domains').value = normalizeDomains(location.hostname, 'http-01')[0]; } catch { /* Hostnames like localhost are not certificate domains. */ }
  }
}
function automaticEnabled(method) { return method === 'http-01' && helperStatus?.capable && document.querySelector('input[name=target]:checked').value === 'site'; }
function renderSavedRecords() {
  const records = (helperStatus?.capable ? helperStatus.records || [] : localStatus().records).filter(record => (record.environment || ENVIRONMENT) === ENVIRONMENT);
  $('certificates-empty').hidden = !!records.length; $('saved-list').replaceChildren();
  const groups = new Map();
  for (const record of records) { const domain = record.domains[0]; if (!groups.has(domain)) groups.set(domain, []); groups.get(domain).push(record); }
  for (const [domain, entries] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
    const card = element('article', null, 'resource-card'); card.append(element('h3', domain, 'certificate-domain'));
    for (const record of entries) {
      const row = element('div', null, 'certificate-entry');
      const state = record.pending ? '待完成验证' : `到期 ${date(new Date(record.notAfter * 1000))}`;
      row.append(element('p', `${state} · ${(record.target || 'site') === 'site' ? '本站' : '其他网站'}`, 'helper'));
      if (record.domains.length > 1) row.append(element('p', '同一张证书还覆盖：' + record.domains.slice(1).join(' · '), 'helper'));
      const actions = element('div', null, 'actions');
      const renew = element('button', record.pending ? '继续验证' : '一键续期', 'secondary'); renew.type = 'button';
      renew.addEventListener('click', () => renewRecord(record)); actions.append(renew);
      if (record.notAfter) {
        const retrieve = element('button', '查看 PEM / KEY 与下载', 'ghost'); retrieve.type = 'button';
        retrieve.addEventListener('click', () => run(async () => {
          if (helperStatus?.capable) renderServerResult(await onlineRequest(online, 'result', { id: record.id }));
          else renderLocalRecord(record);
        })); actions.append(retrieve);
      }
      row.append(actions); card.append(row);
    }
    $('saved-list').append(card);
  }
}
function renderLocalRecord(record) {
  session = { ...record, domain: record.domains[0], validity: { notBefore: new Date(record.notBefore * 1000), notAfter: new Date(record.notAfter * 1000) } };
  renderResult({ certificate: record.certificate, validity: session.validity });
}
async function renewRecord(record) {
  if (busy) return;
  if (!helperStatus?.capable && Date.now() / 1000 < record.renewAt) { renderLocalRecord(record); toast('还没到建议续期日期，已打开现有证书。'); return; }
  session = null; resources = []; invalid = false;
  $('domains').value = record.domains[0]; $('additional-domains').value = record.domains.slice(1).join('\n');
  $('key-algorithm').value = record.keyAlgorithm;
  document.querySelector('input[name=target][value="' + (record.target || 'site') + '"]').checked = true;
  document.querySelector('input[name=method][value="' + (record.method || 'http-01') + '"]').checked = true;
  configureTarget(false); showView('apply'); await prepareConnection();
  if (record.pending) { await run(async () => renderServerPending(await onlineRequest(online, 'pending', { id: record.id }))); return; }
  if (!$('terms').checked) { toast('请阅读并同意当前服务条款后继续续期。'); return; }
  if (helperStatus?.capable) await run(() => serverIssue('renew', { id: record.id, environment: ENVIRONMENT }));
  else await start();
}
function renderServerPending(result) {
  const record = result.record;
  session = { server: true, pending: true, ...record, domain: record.domains[0], certificate: null };
  resources = result.resources; showView('apply'); renderResources();
}
async function serverIssue(action, data) {
  if (!helperStatus?.configured || !helperStatus.authenticated) throw new Error('请先设置密码或登录。');
  $('operation-title').textContent = action === 'renew' ? '正在续期证书…' : '正在申请证书…';
  const automatic = (data.method || session?.method || document.querySelector('input[name=method]:checked').value) === 'http-01'
    && (data.target || session?.target || document.querySelector('input[name=target]:checked').value) === 'site';
  announce(action === 'complete' ? 'Let’s Encrypt 正在检查验证结果，请稍候。'
    : automatic ? '验证文件会自动放好，接下来由 Let’s Encrypt 检查并签发。' : '正在准备本次验证需要的文件或 DNS 记录。'); step(3);
  const result = await onlineRequest(online, action, { ...data, termsAgreed: $('terms').checked, termsUrl });
  if (result.pending) renderServerPending(result); else renderServerResult(result);
  await checkOnline();
}
function renderServerResult(result) {
  const record = result.record;
  $('domain-summary').textContent = record.domains.length === 1 ? record.domains[0] : record.domains.length + ' 个域名 · 同一张证书';
  session = { server: true, ...record, domain: record.domains[0], method: record.method || 'http-01', certificate: result.certificate,
    privateKey: result.privateKey, validity: { notBefore: new Date(record.notBefore * 1000), notAfter: new Date(record.notAfter * 1000) } };
  renderResult({ certificate: result.certificate, privateKey: result.privateKey, validity: session.validity });
  $('recommended-renewal').textContent = date(new Date(record.renewAt * 1000));
  $('reset-page').hidden = false;
  if (result.reused) { $('result-title').textContent = '这张证书还没到续期时间'; announce('已打开现有证书。到建议日期再续期就可以了。'); }
}
async function automaticallyIssue() {
  if (!session || session.method !== 'http-01' || invalid) return;
  if (resources.length) {
    announce('正在自动放置当前网站的验证文件…');
    $('auto-place-status').textContent = '正在写入并核对当前网站的验证网址…';
    await placeOnline(online, resources);
    $('confirmed').checked = true;
    $('auto-place-status').textContent = '文件已写入并核对。证书服务接下来会检查所有域名的公网访问。';
  }
  await completeIssue();
}
function errorMessage(error) {
  let detail = error?.cause?.detail || error?.message || '操作未完成，请稍后重试。';
  const type = error?.type || error?.cause?.type;
  if (type?.includes('rateLimited')) detail = '申请次数暂时达到限制，请按证书服务提示的时间再试。\n' + detail + (error.retryAfter ? '\n下次可重试时间：' + error.retryAfter : '');
  if (error?.name === 'TimeoutError' || error?.name === 'AbortError' || /Failed to fetch|NetworkError|fetch failed/i.test(detail)) detail = '未能连接证书服务。请检查网络后重试，并保留当前页面；已有申请进度不会被清除。';
  if (!$('auth-gate').hidden) { $('auth-error').hidden = false; $('auth-error').textContent = detail; return; }
  $('error').hidden = false; $('error-text').textContent = detail;
  if (session) $('reset-page').hidden = false;
  if (error?.invalidOrder) { invalid = true; $('restart').hidden = false; $('error-restart').hidden = false; $('issue').disabled = true; }
  announce('暂时没成功，请按下面的提示处理。');
  $('error').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
async function run(action, title = '正在处理…') {
  if (busy) return;
  $('operation-title').textContent = title; $('operation-message').textContent = '请稍候。';
  $('error').hidden = true; $('error-restart').hidden = true; setBusy(true);
  $('auth-error').hidden = true;
  try { await action(); } catch (error) { errorMessage(error); }
  finally { setBusy(false); if (invalid) $('issue').disabled = true; }
}
function updateApplyAction() {
  $('start').textContent = automaticEnabled(document.querySelector('input[name=method]:checked').value)
    ? '一键申请' : '申请证书';
}
async function prepareConnection() {
  if (!$('auth-gate').hidden) { $('connection').textContent = '请先登录'; return; }
  client = null; cachedAccount = null; termsUrl = null; $('terms').checked = false; $('terms').disabled = true;
  $('connection').textContent = '正在检查连接'; $('connection').className = 'pill neutral';
  announce('正在连接 Let’s Encrypt 官方证书服务…');
  await run(async () => {
    const environment = ENVIRONMENT;
    const useServer = !!helperStatus?.capable;
    if (useServer) {
      const directory = await onlineRequest(online, 'directory', { environment });
      client = { server: true }; termsUrl = directory.terms;
      $('terms').checked = helperStatus?.authenticated && helperStatus.agreedTerms?.[environment] === termsUrl;
    } else {
      if (!globalThis.isSecureContext || !crypto?.subtle) {
        throw new Error('请在电脑上用 Chrome 打开安装包内的 freessl.html。详细步骤见 readme.md。');
      }
      client = await connect(environment); termsUrl = client.directory.meta.termsOfService;
      $('terms').checked = localStatus().agreedTerms[environment] === termsUrl;
    }
    connectedEnvironment = environment;
    $('terms-link').href = termsUrl; $('terms').disabled = false;
    $('connection').textContent = '已连接 Let’s Encrypt'; $('connection').className = 'pill ready';
    announce('填写域名，选好验证方式，就可以申请了。');
  }, '正在连接 Let’s Encrypt…');
  updateApplyAction();
}
function download(name, data, type = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const link = document.createElement('a'); link.href = url; link.download = name;
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 60000);
  toast('已发起下载，请在 Chrome 下载列表中查看。');
}
function toast(text) { $('toast').textContent = text; $('toast').hidden = false; setTimeout(() => $('toast').hidden = true, 4500); }
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('已复制。'); }
  catch {
    const box = document.createElement('textarea'); box.value = text; box.className = 'clipboard-fallback';
    document.body.append(box); box.select(); const copied = document.execCommand('copy'); box.remove();
    toast(copied ? '已复制。' : '浏览器未允许复制，请使用下载文件。');
  }
}
function element(tag, text, className) {
  const node = document.createElement(tag); if (text != null) node.textContent = text; if (className) node.className = className; return node;
}
function resourceRow(card, label, value, copyLabel) {
  const row = element('div', null, 'resource-row'); row.append(element('span', label, 'field-caption'));
  row.append(element('code', value, 'resource-value'));
  if (copyLabel) { const button = element('button', copyLabel, 'small-button'); button.type = 'button'; button.addEventListener('click', () => copy(value)); row.append(button); }
  card.append(row);
}
function renderResources() {
  document.querySelector('input[name=method][value="' + session.method + '"]').checked = true;
  $('challenge-card').hidden = false; $('result-card').hidden = true; $('reset-page').hidden = false;
  $('confirmed').checked = false; $('restart').hidden = true; invalid = false;
  $('http-instructions').hidden = session.method !== 'http-01' || !resources.length;
  $('manual-files').hidden = session.method !== 'http-01' || !resources.length;
  $('manual-files').open = false;
  $('manual-resource-list').replaceChildren();
  $('dns-instructions').hidden = session.method !== 'dns-01' || !resources.length;
  $('cached-verification').hidden = !!resources.length;
  $('auto-place-panel').hidden = session.method !== 'http-01' || !resources.length || !automaticEnabled(session.method) || !!session.server;
  $('auto-place-status').textContent = '可以自动放置到当前网站的验证目录。';
  $('confirmation-label').textContent = session.method === 'http-01'
    ? '我已逐个打开验证网址，确认每个页面内容都与对应的“应显示的内容”一致。'
    : '我已逐条添加下面的 TXT 记录，并等待 DNS 解析生效。';
  $('confirmation-row').hidden = !resources.length;
  $('issue').textContent = resources.length ? '提交验证并取得证书' : '验证仍有效，直接取得新证书';
  $('switch-dns').hidden = session.method === 'dns-01' || !resources.length;
  $('continue-title').textContent = session.method === 'http-01' ? '上传验证文件' : '添加 DNS 验证记录';
  $('challenge-helper').textContent = session.method === 'http-01'
    ? '域名要指向这个网站，公网要能通过 HTTP 打开验证文件。'
    : '同一个记录名有多个值时，要全部保留，不要互相覆盖。';
  $('resource-list').replaceChildren();
  for (const resource of resources) {
    const card = element('section', null, 'resource-card'); card.append(element('h3', resource.domain));
    if (session.method === 'http-01') {
      resourceRow(card, '验证网址', resource.url);
      resourceRow(card, '应显示的内容', resource.content);
      const actions = element('div', null, 'actions');
      const link = element('a', '打开验证网址 ↗', 'text-link'); link.href = resource.url; link.target = '_blank'; link.rel = 'noopener noreferrer';
      actions.append(link); card.append(actions);
      const manual = element('section', null, 'resource-card'); manual.append(element('h3', resource.domain));
      resourceRow(manual, '文件目录', '.well-known/acme-challenge/');
      resourceRow(manual, '文件名', resource.name, '复制文件名');
      resourceRow(manual, '文件内容', resource.content, '复制内容');
      $('manual-resource-list').append(manual);
    } else {
      resourceRow(card, '记录类型', 'TXT');
      resourceRow(card, '完整记录名', resource.name.replace(/\.$/, ''), '复制记录名');
      resourceRow(card, '记录值', resource.content, '复制记录值');
    }
    $('resource-list').append(card);
  }
  $('setup-card').classList.add('completed'); step(2);
  announce(resources.length
    ? session.method === 'http-01' ? '验证文件已准备好，按下面的步骤上传。' : 'TXT 记录已准备好，按下面的步骤添加。'
    : '域名验证仍然有效，可以直接取得证书。');
  $('challenge-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
async function start() {
  await run(async () => {
    if (!client || connectedEnvironment !== ENVIRONMENT) throw new Error('请先点击“重新连接”，连上 Let’s Encrypt 后再申请。');
    if (!$('terms').checked || !termsUrl) throw new Error('请先阅读并同意 Let’s Encrypt 服务条款。');
    const method = document.querySelector('input[name=method]:checked').value;
    const domains = normalizeDomains($('domains').value + '\n' + $('additional-domains').value, method); $('domains').value = domains[0]; $('additional-domains').value = domains.slice(1).join('\n');
    if (client.server) {
      await serverIssue('issue', { domains, environment: connectedEnvironment, keyAlgorithm: $('key-algorithm').value, method, target: document.querySelector('input[name=target]:checked').value }); return;
    }
    announce('正在为你的域名申请 Let’s Encrypt 证书，请稍候。');
    // Cache the account immediately, even if creating an order subsequently fails.
    cachedAccount ||= await client.createAccount({ emails: [] });
    session = await createSession({ client, account: cachedAccount, environment: connectedEnvironment, domains, method, keyAlgorithm: $('key-algorithm').value });
    session.target = document.querySelector('input[name=target]:checked').value;
    $('domain-summary').textContent = domains.length === 1 ? domains[0] : domains.length + ' 个域名 · 同一张证书';
    resources = await challengeResources(session); renderResources();
  }, '正在申请证书…');
}
async function restart(method = session?.method) {
  await run(async () => {
    if (session?.server && session.pending) { await serverIssue('issue', { domains: session.domains, environment: session.environment, keyAlgorithm: session.keyAlgorithm, method, target: session.target || 'other', restart: true }); return; }
    if (!session) return;
    announce('正在重新生成本次验证材料…');
    const status = await readOrder(session);
    if (invalid || status.status === 'invalid') {
      session = await createSession({ client, account: cachedAccount, environment: connectedEnvironment, domains: session.domains, method, keyAlgorithm: session.keyAlgorithm });
    }
    session.target = document.querySelector('input[name=target]:checked').value;
    resources = await challengeResources(session, method); renderResources();
  });
}
async function issue() {
  if (resources.length && !$('confirmed').checked && !session?.certificate) return;
  await run(completeIssue, '正在申请证书…');
}
async function completeIssue() {
    if (session?.server && session.pending) { await serverIssue('complete', { id: session.id, environment: session.environment, confirmed: $('confirmed').checked }); return; }
    step(3); announce('正在提交验证，请保留此页面…');
    const result = await issueCertificate(session, { onStatus: status => announce(
      status === 'pending' ? 'Let’s Encrypt 正在验证域名，通常需要几秒到几分钟…' :
      status === 'finalizing' ? '域名验证已通过，正在提交证书签发请求…' : '正在等待 Let’s Encrypt 签发证书…') });
    renderResult(result);
    await saveLocalCertificate(session, termsUrl); renderSavedRecords();
}
function renderResult(result) {
  showView('certificates'); step(4); $('result-card').hidden = false; $('challenge-card').hidden = true;
  $('issued-domain').textContent = session.domains.join(' · ');
  $('issued-until').textContent = date(result.validity.notAfter);
  $('recommended-renewal').textContent = date(new Date(result.validity.notBefore.getTime() + (result.validity.notAfter - result.validity.notBefore) * 2 / 3));
  $('result-title').textContent = '证书申请成功';
  $('result-state').textContent = 'Let’s Encrypt 已签发';
  $('cert-output').value = result.certificate;
  $('key-output').value = session.privateKey;
  $('renewal-note').textContent = session.server
    ? '下次在“我的证书”找到这个域名，点击“一键续期”就可以继续。'
    : '下次用同一文件和浏览器打开，在“我的证书”点击“一键续期”。';
  $('site-links').replaceChildren();
  for (const domain of session.domains.filter(domain => !domain.startsWith('*.'))) {
    const link = element('a', '打开 ' + domain + ' ↗', 'text-link'); link.href = 'https://' + domain; link.target = '_blank'; link.rel = 'noopener noreferrer'; $('site-links').append(link);
  }
  $('result-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
  announce('证书 PEM 和私钥 KEY 已显示，可以直接复制到主机面板。');
}

function resetPage() {
  if (busy) return;
  if (session && !session.server && !session.certificate && !confirm('当前申请尚未完成。重新办理会放弃本页面的这次进度，是否继续？')) return;
  session = null; resources = []; invalid = false;
  $('challenge-card').hidden = true; $('result-card').hidden = true; $('reset-page').hidden = true;
  $('setup-card').classList.remove('completed'); $('resource-list').replaceChildren();
  $('manual-files').hidden = true; $('manual-files').open = false; $('manual-resource-list').replaceChildren();
  $('key-output').value = '';
  $('cert-output').value = ''; $('domain-summary').textContent = '填写你的域名'; $('error').hidden = true;
  $('confirmed').checked = false; step(1); setBusy(false); updateApplyAction();
  showView('apply'); announce('可以填写下一个域名了。'); $('setup-card').scrollIntoView({ behavior: 'smooth' });
}
$('reset-page').addEventListener('click', resetPage);
$('nav-apply').addEventListener('click', () => { if (busy) return; if (session?.certificate) resetPage(); showView('apply'); });
$('nav-certificates').addEventListener('click', () => { if (!busy) { renderSavedRecords(); showView('certificates'); } });
document.querySelectorAll('input[name=target]').forEach(input => input.addEventListener('change', async () => { configureTarget(); if (!session) await prepareConnection(); }));

$('terms').addEventListener('change', () => setBusy(busy));
$('reconnect').addEventListener('click', () => session?.server ? run(async () => {
  await checkOnline(); announce('PHP 已重新检测，可以到“我的证书”查看进度。');
}) : session ? run(async () => {
  await readOrder(session);
  if (!session.certificate && $('challenge-card').hidden) {
    resources = await challengeResources(session); renderResources();
  } else announce('已重新连接，可以继续申请了。');
}) : prepareConnection());
$('start').addEventListener('click', start);
$('confirmed').addEventListener('change', () => setBusy(busy));
$('issue').addEventListener('click', issue);
$('switch-dns').addEventListener('click', () => restart('dns-01'));
$('restart').addEventListener('click', () => restart());
$('error-restart').addEventListener('click', () => restart());
$('check-online').addEventListener('click', async () => { if (busy) return; await checkOnline(); if (!session) await prepareConnection(); });
$('auto-place').addEventListener('click', () => run(automaticallyIssue));
$('setup-form').addEventListener('submit', async event => {
  event.preventDefault();
  await run(async () => {
    if ($('setup-password').value !== $('confirm-password').value) throw new Error('两次输入的密码不一致。');
    if (helperStatus?.capable) await onlineRequest(online, 'set-password', { password: $('setup-password').value, confirmPassword: $('confirm-password').value });
    else await setLocalPassword($('setup-password').value, $('confirm-password').value);
    $('setup-form').reset(); await checkOnline(); toast('密码已设置，已自动登录。');
  });
  if (!session) await prepareConnection();
});
$('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  await run(async () => { if (helperStatus?.capable) await onlineRequest(online, 'login', { password: $('login-password').value }); else await loginLocal($('login-password').value); $('login-form').reset(); await checkOnline(); });
  if (!session) await prepareConnection();
});
$('logout-online').addEventListener('click', () => run(async () => {
  if (helperStatus?.capable) await onlineRequest(online, 'logout', {}); else logoutLocal();
  session = null; resources = []; $('cert-output').value = ''; $('key-output').value = ''; $('result-card').hidden = true;
  await checkOnline();
}));
document.querySelectorAll('input[name=method]').forEach(input => input.addEventListener('change', prepareConnection));
$('download-challenge-zip').addEventListener('click', () => {
  const files = Object.fromEntries(resources.map(resource => ['.well-known/acme-challenge/' + resource.name, strToU8(resource.content)]));
  download(session.domain.replace(/\*/g, 'wildcard') + '-http-validation.zip', zipSync(files, { level: 0 }), 'application/zip');
});
$('copy-cert').addEventListener('click', () => copy(session.certificate));
$('copy-key').addEventListener('click', () => copy(session.privateKey));
$('download-cert').addEventListener('click', () => download('fullchain.pem', session.certificate));
$('download-key').addEventListener('click', () => download('privkey.pem', session.privateKey));
$('download-result-zip').addEventListener('click', () => {
  const name = session.domain.replace(/\*/g, 'wildcard');
  const text = `域名：${session.domains.join(", ")}\n签发机构：Let’s Encrypt\n到期日期：${date(session.validity.notAfter)}\n\nfullchain.pem：证书 PEM，填入主机面板的证书框。\nprivkey.pem：私钥 KEY，填入主机面板的私钥框。\n\n保存后打开网站，确认 HTTPS 正常。证书包里有私钥，请留在自己的电脑，不要放到网站公开目录。\n下次续期：打开 freessl.html，在“我的证书”找到对应域名，点击“一键续期”。本站 PHP 文件验证会自动完成；DNS 或手动文件验证按页面更新记录或文件。\n`;
  download(name + '-certificate.zip', zipSync({
    'fullchain.pem': strToU8(session.certificate), 'privkey.pem': strToU8(session.privateKey), 'readme.txt': strToU8(text)
  }, { level: 0 }), 'application/zip');
});
window.addEventListener('beforeunload', event => {
  if (busy || (session && !session.server && !session.certificate)) { event.preventDefault(); event.returnValue = ''; }
});
// Wait for PHP detection before choosing a signer. Plain HTTP never tries
// browser WebCrypto when the server can sign, including the first certificate.
async function initialize() { await checkOnline(); await prepareConnection(); }
initialize();

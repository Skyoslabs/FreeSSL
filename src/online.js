// Capture the same-site connection before installing the browser ACME guard.
// PHP signs on the server, so its mode also works on a plain HTTP website.
const siteFetch = globalThis.fetch.bind(globalThis);
export function onlineContext(location) {
  const online = ['http:', 'https:'].includes(location.protocol);
  return { online,
    helper: online ? new URL('freessl.php', location.href).href : null, origin: location.origin };
}
export async function onlineRequest(context, action, data) {
  if (!context.online) throw new Error('PHP 模式需要通过网站地址打开 freessl.html。');
  const url = new URL(context.helper); url.searchParams.set('action', action);
  const response = await siteFetch(url.href, {
    method: data === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    referrerPolicy: 'same-origin', signal: AbortSignal.timeout(['issue', 'renew', 'complete'].includes(action) ? 250000 : 30000),
    headers: data === undefined ? {} : { 'Content-Type': 'application/json' },
    ...(data === undefined ? {} : { body: JSON.stringify(data) })
  });
  let body;
  try { body = await response.json(); } catch { throw new Error('没有检测到可用的 PHP。请用电脑打开安装包里的 freessl.html，具体步骤见 readme.md。'); }
  if (!response.ok) { const error = new Error(body.message || 'PHP 操作未完成。'); error.invalidOrder = !!body.invalidOrder; throw error; }
  if (body.helper !== 'freessl' || body.version !== 2) throw new Error('PHP 助手与 HTML 不配套，请重新上传同一个安装包中的两个文件。');
  return body;
}
export const probeOnline = context => onlineRequest(context, 'status');
export async function placeOnline(context, resources) {
  const files = resources.map(({ name, content }) => ({ name, content }));
  await onlineRequest(context, 'write', { files });
  for (const resource of files) {
    const url = new URL('/.well-known/acme-challenge/' + resource.name, context.origin);
    const response = await siteFetch(url.href, { cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(15000) });
    if (!response.ok || (await response.text()).trim() !== resource.content) throw new Error('验证网址没有返回对应文件内容。请检查 .well-known 路径，或使用 DNS 引导。');
  }
  return resources.length;
}

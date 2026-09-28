import { PHP } from '@php-wasm/universal';
import { loadNodeRuntime } from '@php-wasm/node';
import { readFile } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
// Real PHP 8.4, isolated in WordPress's official WebAssembly filesystem.
// This runtime is a development dependency, absent from the deployment package.
export async function phpFixture({ transport, installDirectory = '/site' } = {}) {
  const php = new PHP(await loadNodeRuntime('8.4', { emscriptenOptions: { processId: process.pid } }));
  php.mkdir('/site');
  let folder = '';
  for (const part of installDirectory.slice(1).split('/')) {
    folder += '/' + part;
    if (!php.fileExists(folder)) php.mkdir(folder);
  }
  let source = await readFile(fileURLToPath(new URL('../freessl.php', import.meta.url)), 'utf8');
  if (transport) {
    // Test-only transport replacement in the isolated WASM filesystem. The
    // production file has no mock hook. All PHP signing/storage still runs.
    const start = source.indexOf('function assistantFetchRaw('), end = source.indexOf('class AssistantACME', start);
    source = source.slice(0, start) + `function assistantFetchRaw(string $url, $data): array { return json_decode(post_message_to_js(json_encode(['url'=>$url,'data'=>$data])), true, 64, JSON_THROW_ON_ERROR); }\n` + source.slice(end);
    php.onMessage(async message => {
      const { url, data } = JSON.parse(message);
      const response = await transport(url, { method: data === false ? 'HEAD' : data == null ? 'GET' : 'POST', ...(typeof data === 'string' ? { body: data } : {}) });
      return JSON.stringify({ code: String(response.status), headers: Object.fromEntries(response.headers), body: await response.text() });
    });
  }
  php.writeFile(installDirectory + '/freessl.php', source);
  const token = randomBytes(32).toString('base64url');
  const authCookie = 'ssl_assistant_session=' + token;
  const guard = '<?php http_response_code(404); exit; ?>\n';
  const configure = (extra = {}) => {
    php.writeFile(installDirectory + '/freessl-password.php', guard + JSON.stringify({ password_hash: 'isolated-fixture-configured', sessions: { [createHash('sha256').update(token).digest('hex')]: Math.floor(Date.now() / 1000) + 30 * 86400 } }));
    php.writeFile(installDirectory + '/ssl-helper.config.php', guard + JSON.stringify(extra));
  };
  async function request(action, files, overrides = {}) {
    const body = files == null ? undefined : JSON.stringify(Array.isArray(files) ? { files } : files);
    const response = await php.runStream({
      scriptPath: installDirectory + '/freessl.php', relativeUri: installDirectory.slice('/site'.length) + '/freessl.php?action=' + action,
      protocol: overrides.server?.HTTPS === 'off' ? 'http' : 'https', method: body == null ? 'GET' : 'POST', ...(body != null ? { body: new TextEncoder().encode(body) } : {}),
      headers: { Host: overrides.server?.HTTP_HOST || 'site.test', 'Content-Type': 'application/json', Cookie: authCookie, ...overrides.headers },
      $_SERVER: { DOCUMENT_ROOT: '/site', HTTP_HOST: 'site.test', HTTPS: 'on', HTTP_SEC_FETCH_SITE: 'same-origin', HTTP_ORIGIN: 'https://site.test', ...overrides.server,
        ...(overrides.server?.HTTPS === 'off' ? { HTTPS: '' } : {}) }
    });
    const [raw, status, errors, headers] = await Promise.all([response.stdoutText, response.httpStatusCode, response.stderrText, response.headers]);
    return { raw, body: JSON.parse(raw), status, errors, headers };
  }
  return { php, configure, request, guard, authCookie };
}

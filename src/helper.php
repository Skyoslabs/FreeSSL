<?php
// Build template: bundled with the pinned, unmodified ACMECert sources.
ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
const STORAGE_GUARD = "<?php http_response_code(404); exit; ?>\n";
const COOKIE_NAME = 'ssl_assistant_session';
const ACCESS_DAYS = 30;

function reply(int $status, array $data): void {
    http_response_code($status);
    echo json_encode(['helper' => 'freessl', 'version' => 2] + $data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function fail(int $status, string $message): void { reply($status, ['ok' => false, 'message' => $message]); }
function ordinary(string $path): void {
    clearstatcache(true, $path);
    if (is_link($path) || (file_exists($path) && !is_file($path))) fail(409, '运行文件路径异常，请在主机面板检查。');
}
function guardedRead(string $path): string {
    ordinary($path);
    $text = @file_get_contents($path);
    if (!is_string($text) || !str_starts_with($text, STORAGE_GUARD)) fail(500, '运行数据格式不正确，请在主机面板检查。');
    return substr($text, strlen(STORAGE_GUARD));
}
function guardedWrite(string $path, string $text): void {
    ordinary($path);
    $temporary = dirname($path) . '/ssl-tmp-' . bin2hex(random_bytes(12)) . '.php';
    $handle = @fopen($temporary, 'x');
    if (!$handle) fail(500, 'PHP 无权保存运行数据，请检查网站目录写入权限。');
    @chmod($temporary, 0600);
    $data = STORAGE_GUARD . $text;
    $written = fwrite($handle, $data) === strlen($data) && fflush($handle);
    fclose($handle);
    ordinary($path);
    if (!$written || !@rename($temporary, $path)) { @unlink($temporary); fail(500, '运行数据未完整保存，请检查权限后重试。'); }
}
function loadConfig(string $path): array {
    ordinary($path);
    if (!file_exists($path)) return [];
    try { $data = json_decode(guardedRead($path), true, 32, JSON_THROW_ON_ERROR); }
    catch (Throwable $error) { fail(500, '授权数据格式不正确，请在主机面板检查。'); }
    if (!is_array($data)) fail(500, '授权数据格式不正确。');
    return $data;
}
function saveConfig(string $path, array $data): void { guardedWrite($path, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)); }
function lockState(string $root) {
    $path = $root . '/ssl-helper.lock.php'; ordinary($path);
    if (!file_exists($path)) { $h = @fopen($path, 'x'); if ($h) { fwrite($h, STORAGE_GUARD); fclose($h); @chmod($path, 0600); } }
    $lock = @fopen($path, 'r+');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) fail(409, '另一个操作正在进行，请稍后再试。');
    return $lock;
}
function secureRequest(): bool { return ($_SERVER['HTTPS'] ?? '') === 'on' || ($_SERVER['HTTPS'] ?? '') === '1'; }
function setSessionCookie(string $token, int $expiry): void {
    setcookie(COOKIE_NAME, $token, ['expires' => $expiry, 'path' => '/', 'secure' => secureRequest(), 'httponly' => true, 'samesite' => 'Strict']);
}
function sessionToken(): string {
    $token = $_COOKIE[COOKIE_NAME] ?? '';
    return is_string($token) ? $token : '';
}
function authenticated(array $config): bool {
    $token = sessionToken();
    return isset($config['password_hash']) && preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $token) === 1
        && ($config['sessions'][hash('sha256', $token)] ?? 0) > time();
}
function startLogin(array &$config): void {
    $config['sessions'] = array_filter($config['sessions'] ?? [], static fn($expiry) => is_int($expiry) && $expiry > time());
    asort($config['sessions']);
    while (count($config['sessions']) >= 10) array_shift($config['sessions']);
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $expiry = time() + ACCESS_DAYS * 86400;
    $config['sessions'][hash('sha256', $token)] = $expiry;
    setSessionCookie($token, $expiry);
}
function chosenPassword(array $body): string {
    $password = $body['password'] ?? null;
    if (!is_string($password) || str_contains($password, "\0") || preg_match_all('/./us', $password) < 8) fail(400, '密码至少需要 8 个字符。');
    if (strlen($password) > 72) fail(400, '密码太长，请缩短后重试。');
    if (!isset($body['confirmPassword']) || !is_string($body['confirmPassword']) || !hash_equals($password, $body['confirmPassword'])) fail(400, '两次输入的密码不一致。');
    return $password;
}
function sameOrigin(): void {
    $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
    if ($site !== '' && $site !== 'same-origin') fail(403, '只能从当前网站的证书助手提交。');
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin !== '') {
        $expected = (secureRequest() ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? '');
        if (strtolower(rtrim($origin, '/')) !== strtolower($expected)) fail(403, '请求来源与当前网站不一致。');
    }
}
function inputBody(): array {
    if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) fail(415, '请求必须使用 JSON。');
    if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 32768) fail(413, '请求过大。');
    $raw = file_get_contents('php://input', false, null, 0, 32769);
    if ($raw === false || strlen($raw) > 32768) fail(413, '请求过大。');
    try { $body = json_decode($raw, true, 16, JSON_THROW_ON_ERROR); } catch (Throwable $error) { fail(400, '请求格式无效。'); }
    if (!is_array($body)) fail(400, '请求格式无效。');
    return $body;
}
function environment(array $body): string {
    $env = $body['environment'] ?? 'production';
    if ($env !== 'production') fail(400, '仅支持正式证书签发。');
    return $env;
}
function domains(array $input, string $method = 'http-01'): array {
    if (count($input) < 1 || count($input) > 100) fail(400, '一张证书需要 1 到 100 个域名。');
    $out = [];
    foreach ($input as $value) {
        if (!is_string($value)) fail(400, '域名格式不正确。');
        $value = strtolower($value);
        $check = $value;
        if (str_starts_with($value, '*.')) {
            if ($method !== 'dns-01') fail(400, '泛域名需要选择 DNS 验证。');
            $check = substr($value, 2);
        }
        if (strlen($value) > 253 || strpos($value, '.') === false || filter_var($value, FILTER_VALIDATE_IP)) fail(400, '请填写完整域名。');
        foreach (explode('.', $check) as $label) if (!preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/D', $label)) fail(400, '域名格式不正确。');
        $out[$value] = true;
    }
    $result = array_keys($out); sort($result); return $result;
}
function placeFiles(string $root, array $files): array {
    if (count($files) < 1 || count($files) > 100) fail(400, '一次只能放置 1 到 100 个验证文件。');
    $validated = [];
    foreach ($files as $file) {
        if (!is_array($file) || count($file) !== 2 || !isset($file['name'], $file['content']) || !is_string($file['name']) || !is_string($file['content'])) fail(400, '验证文件字段无效。');
        $name = $file['name']; $content = $file['content'];
        if (!preg_match('/\A[A-Za-z0-9_-]{16,128}\z/D', $name) || !preg_match('/\A[A-Za-z0-9_-]{16,128}\.[A-Za-z0-9_-]{43}\z/D', $content) || !str_starts_with($content, $name . '.')) fail(400, '只能写入合法的 ACME 验证文件。');
        if (isset($validated[$name]) && $validated[$name] !== $content) fail(409, '验证文件名冲突。');
        $validated[$name] = $content;
    }
    $directory = $root;
    foreach (['.well-known', 'acme-challenge'] as $part) {
        $directory .= '/' . $part;
        if (is_link($directory) || (file_exists($directory) && !is_dir($directory))) fail(409, '验证目录不是普通目录，请在主机面板检查。');
        if (!is_dir($directory) && !@mkdir($directory, 0755)) fail(500, 'PHP 无法在网站根目录创建验证文件夹。请检查目录权限，或改用 DNS 验证。');
        if (realpath($directory) !== $directory) fail(409, '验证目录路径异常。');
    }
    $created = [];
    foreach ($validated as $name => $content) {
        $destination = $directory . '/' . $name; ordinary($destination);
        if (is_file($destination)) {
            if (@file_get_contents($destination) === $content) continue;
            fail(409, '同名验证文件已存在且内容不同，请重新申请。');
        }
        $handle = @fopen($destination, 'x');
        if (!$handle) fail(500, '验证文件创建失败，请检查权限。');
        $written = fwrite($handle, $content) === strlen($content) && fflush($handle); fclose($handle);
        if (!$written) { @unlink($destination); fail(500, '验证文件未完整写入。'); }
        @chmod($destination, 0644); $created[$destination] = $content;
    }
    return $created;
}

// Isolated transport adapter: official hosts only, TLS verification, no redirects,
// bounded requests. The upstream transport otherwise follows arbitrary redirects.
function assistantFetchRaw(string $url, $data): array {
    $method = $data === false ? 'HEAD' : ($data === null ? 'GET' : 'POST');
    $requestHeaders = $method === 'POST' ? ['Content-Type: application/jose+json'] : [];
    if (extension_loaded('curl')) {
        $headers = []; $handle = curl_init($url);
        curl_setopt_array($handle, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_TIMEOUT => 25, CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_CUSTOMREQUEST => $method, CURLOPT_NOBODY => $method === 'HEAD',
            CURLOPT_HTTPHEADER => $requestHeaders, CURLOPT_USERAGENT => 'freessl/1.0',
            CURLOPT_HEADERFUNCTION => static function ($handle, $line) use (&$headers) { $headers[] = $line; return strlen($line); }]);
        if ($method === 'POST') curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
        $body = curl_exec($handle); $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE); curl_close($handle);
        if ($body === false) throw new RuntimeException('无法连接官方证书服务，请检查服务器网络和 CA 信任配置。');
    } else {
        $options = ['http' => ['method' => $method, 'header' => $requestHeaders, 'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 25], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]];
        if ($method === 'POST') $options['http']['content'] = $data;
        $body = @file_get_contents($url, false, stream_context_create($options));
        $headers = PHP_VERSION_ID >= 80400 ? http_get_last_response_headers() : ($http_response_header ?? []);
        $status = 0;
        foreach ($headers ?? [] as $line) if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $line, $match)) $status = (int) $match[1];
        if ($body === false) throw new RuntimeException('无法连接官方证书服务，请检查服务器网络和 CA 信任配置。');
    }
    $parsed = [];
    foreach ($headers as $line) {
        if (str_starts_with($line, 'HTTP/')) { $parsed = []; continue; }
        $pair = explode(':', $line, 2);
        if (count($pair) === 2) $parsed[strtolower(trim($pair[0]))] = trim($pair[1]);
    }
    return ['code' => (string) $status, 'headers' => $parsed, 'body' => $body];
}
class AssistantACME extends \skoerfgen\ACMECert\ACMECert {
    private float $deadline;
    private string $officialHost;
    public function __construct(string $environment) {
        if ($environment !== 'production') throw new RuntimeException('仅支持正式证书签发。');
        $this->officialHost = 'acme-v02.api.letsencrypt.org';
        parent::__construct('https://' . $this->officialHost . '/directory');
        $this->deadline = microtime(true) + 210; $this->setLogger(false);
    }
    // The upstream all-in-one callback is synchronous. This small adapter reuses
    // its signing, CSR and transport for RFC 8555 orders resumed across requests.
    public function beginManual(array $domains, string $method): array {
        $this->getAccountID();
        $ret = $this->request('newOrder', ['identifiers' => array_map(static fn($domain) => ['type' => 'dns', 'value' => $domain], $domains)]);
        $order = $ret['body']; $url = $ret['headers']['location'] ?? '';
        if (!is_array($order) || $url === '') throw new RuntimeException('订单无效。');
        $resources = [];
        foreach ($order['authorizations'] as $authorizationURL) {
            $authorization = $this->request($authorizationURL)['body'];
            if (($authorization['status'] ?? '') === 'valid') continue;
            $domain = $authorization['identifier']['value'];
            $displayDomain = ($authorization['wildcard'] ?? false) ? '*.' . $domain : $domain;
            if (!in_array($displayDomain, $domains, true)) throw new RuntimeException('验证域名无效。');
            $found = false;
            foreach ($authorization['challenges'] as $challenge) {
                if ($challenge['type'] !== $method) continue;
                $found = true; $authorizationValue = $this->keyAuthorization($challenge['token']);
                $resources[] = $method === 'http-01'
                    ? ['domain' => $displayDomain, 'name' => $challenge['token'], 'content' => $authorizationValue, 'url' => 'http://' . $domain . '/.well-known/acme-challenge/' . $challenge['token']]
                    : ['domain' => $displayDomain, 'name' => '_acme-challenge.' . $domain, 'content' => $this->base64url(hash('sha256', $authorizationValue, true))];
                break;
            }
            if (!$found) throw new RuntimeException('所选验证方式不可用。');
        }
        return ['orderURL' => $url, 'resources' => $resources];
    }
    private function awaitManual(string $url, string $success): array {
        for ($attempt = 0; $attempt < 80; $attempt++) {
            $data = $this->request($url)['body']; $status = $data['status'] ?? '';
            if ($status === $success || ($success === 'ready' && $status === 'valid')) return $data;
            if (in_array($status, ['invalid', 'expired', 'deactivated', 'revoked'], true)) throw new AssistantInvalidOrder();
            usleep(1000000);
        }
        throw new RuntimeException('等待验证超时。');
    }
    public function finishManual(array $pending, string $privateKey): string {
        $this->getAccountID();
        $order = $this->request($pending['orderURL'])['body'];
        if (($order['status'] ?? '') === 'invalid') throw new AssistantInvalidOrder();
        if (($order['status'] ?? '') === 'pending') {
            foreach ($order['authorizations'] as $url) {
                $auth = $this->request($url)['body'];
                if (($auth['status'] ?? '') === 'valid') continue;
                if (in_array($auth['status'] ?? '', ['invalid', 'expired', 'revoked', 'deactivated'], true)) throw new AssistantInvalidOrder();
                $challengeURL = null;
                foreach ($auth['challenges'] as $challenge) if ($challenge['type'] === $pending['method']) { $challengeURL = $challenge['url']; break; }
                if (!$challengeURL) throw new RuntimeException('验证方式无效。');
                $this->request($challengeURL, new \stdClass()); $this->awaitManual($url, 'valid');
            }
            $order = $this->awaitManual($pending['orderURL'], 'ready');
        }
        if (($order['status'] ?? '') === 'ready') {
            $csr = $this->generateCSR($privateKey, $pending['domains']);
            $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $csr), true);
            if ($der === false) throw new RuntimeException('CSR 无效。');
            $order = $this->request($order['finalize'], ['csr' => $this->base64url($der)])['body'];
        }
        if (($order['status'] ?? '') !== 'valid') $order = $this->awaitManual($pending['orderURL'], 'valid');
        if (!isset($order['certificate'])) throw new RuntimeException('证书尚未生成。');
        return $this->request($order['certificate'])['body'];
    }
    protected function http_request($url, $data = null) {
        $parts = parse_url($url);
        if (!$parts || ($parts['scheme'] ?? '') !== 'https' || ($parts['host'] ?? '') !== $this->officialHost || isset($parts['port']) || isset($parts['user']) || isset($parts['pass'])) throw new RuntimeException('已阻止连接到非官方证书接口。');
        if (microtime(true) > $this->deadline) throw new RuntimeException('签发等待超时。稍后打开页面检查结果，或改用本地引导。');
        $ret = assistantFetchRaw($url, $data);
        if (isset($ret['headers']['replay-nonce'])) $this->nonce = $ret['headers']['replay-nonce'];
        $type = strtolower(explode(';', $ret['headers']['content-type'] ?? '')[0]);
        if (in_array($type, ['application/json', 'application/problem+json'], true)) {
            $ret['body'] = json_decode($ret['body'], true, 64, JSON_THROW_ON_ERROR);
            $problem = $ret['body']['error'] ?? ($type === 'application/problem+json' ? $ret['body'] : null);
            if (is_array($problem)) throw new \skoerfgen\ACMECert\ACME_Exception($problem['type'] ?? 'acme:error', $problem['detail'] ?? '官方证书服务拒绝了本次操作。');
        }
        if ((int) $ret['code'] < 200 || (int) $ret['code'] >= 300) throw new RuntimeException('官方证书服务返回 HTTP ' . $ret['code'] . '，请稍后重试。');
        return $ret;
    }
}
class AssistantInvalidOrder extends \RuntimeException {}
function records(array $config): array {
    $records = $config['records'] ?? [];
    foreach ($config['pending'] ?? [] as $id => $pending) {
        $records[$id] = ($records[$id] ?? []) + array_intersect_key($pending, array_flip(['id', 'domains', 'environment', 'keyAlgorithm', 'method', 'target']));
        $records[$id]['pending'] = true;
    }
    return array_values(array_filter($records, static fn($record) => ($record['environment'] ?? 'production') === 'production'));
}
function pendingData(array $pending): array {
    return ['ok' => true, 'pending' => true, 'record' => array_intersect_key($pending, array_flip(['id', 'domains', 'environment', 'keyAlgorithm', 'method', 'target'])), 'resources' => $pending['resources']];
}
function resultData(array $record, string $root, bool $reused = false): array {
    return ['ok' => true, 'record' => $record, 'certificate' => guardedRead($root . '/' . $record['certificateFile']),
        'privateKey' => guardedRead($root . '/' . $record['privateKeyFile']), 'reused' => $reused];
}

$root = realpath(__DIR__); $documentRoot = realpath($_SERVER['DOCUMENT_ROOT'] ?? '');
if (!$root || !$documentRoot || !is_dir($documentRoot)
    || ($root !== $documentRoot && !str_starts_with($root, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR))) {
    fail(409, '请将 freessl.html 和 freessl.php 放在同一个网站目录内。可以使用网站根目录，也可以使用它下面的子目录。');
}
$configPath = $root . '/ssl-helper.config.php';
$passwordPath = $root . '/freessl-password.php';
$config = loadConfig($configPath); $access = loadConfig($passwordPath);
// Move an existing installation's login fields once. Certificates/accounts stay
// in place; deleting the separate password file can then reset login only.
if (isset($config['password_hash'])) {
    $migrationLock = lockState($root);
    $config = loadConfig($configPath); $access = loadConfig($passwordPath);
    $loginFields = array_flip(['password_hash', 'sessions', 'login_failures', 'login_blocked_until']);
    if (!file_exists($passwordPath) && isset($config['password_hash'])) {
        $access = array_intersect_key($config, $loginFields); saveConfig($passwordPath, $access);
    }
    $config = array_diff_key($config, $loginFields); saveConfig($configPath, $config);
    flock($migrationLock, LOCK_UN); fclose($migrationLock);
}
$configured = isset($access['password_hash']); $signedIn = authenticated($access);
$capable = PHP_VERSION_ID >= 80100 && extension_loaded('openssl') && (extension_loaded('curl') || (bool) ini_get('allow_url_fopen')) && is_writable($root);
$action = $_GET['action'] ?? ''; $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'GET' && $action === 'status') reply(200, ['ok' => true, 'configured' => $configured, 'capable' => $capable, 'authenticated' => $signedIn, 'records' => $signedIn ? records($config) : [], 'agreedTerms' => $signedIn ? ($config['agreedTerms'] ?? []) : [], 'message' => $capable ? '' : '需要 PHP 8.1+、OpenSSL、cURL 或 allow_url_fopen，以及网站目录写入权限。']);
if ($method !== 'POST') fail(405, '不支持这个操作。');
sameOrigin(); $body = inputBody();
if ($action === 'directory') {
    if (!$capable) fail(503, 'PHP 环境不能自动签发，请使用本地引导。');
    try { $ac = new AssistantACME(environment($body)); $terms = $ac->getTermsURL();
        if (parse_url($terms, PHP_URL_SCHEME) !== 'https' || parse_url($terms, PHP_URL_HOST) !== 'letsencrypt.org') throw new RuntimeException();
        reply(200, ['ok' => true, 'terms' => $terms]);
    } catch (Throwable $error) { fail(502, '无法连接官方证书服务，请检查服务器网络和 CA 信任配置。'); }
}
if (!in_array($action, ['set-password', 'login', 'logout', 'write', 'issue', 'renew', 'result', 'complete', 'pending'], true)) fail(405, '不支持这个操作。');
if (!in_array($action, ['set-password', 'login', 'logout'], true)) {
    if (!$configured) fail(503, '首次使用，请先设置密码。');
    if (!$signedIn) fail(403, '请先输入密码登录。');
}
// One fixed lock serializes configuration and issuance; never overwrite a symlink.
$lock = lockState($root);
$config = loadConfig($configPath); $access = loadConfig($passwordPath); $configured = isset($access['password_hash']);
if ($action === 'set-password') {
    if ($configured) fail(409, '密码已经设置，请直接登录。');
    if (!$capable) fail(503, 'PHP 环境不能自动签发，请使用本地引导。');
    $password = chosenPassword($body);
    try { $access['password_hash'] = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]); }
    catch (Throwable $error) { fail(500, '密码设置失败，请检查 PHP 环境后重试。'); }
    startLogin($access); saveConfig($passwordPath, $access);
    reply(200, ['ok' => true]);
}
if ($action === 'login') {
    if (!$configured) fail(409, '首次使用，请先设置密码。');
    if (($access['login_blocked_until'] ?? 0) > time()) fail(429, '密码尝试次数过多，请一分钟后再试。');
    $password = $body['password'] ?? '';
    if (!is_string($password) || strlen($password) > 72 || str_contains($password, "\0") || !password_verify($password, $access['password_hash'])) {
        $access['login_failures'] = ($access['login_failures'] ?? 0) + 1;
        if ($access['login_failures'] >= 5) { $access['login_blocked_until'] = time() + 60; $access['login_failures'] = 0; }
        saveConfig($passwordPath, $access); fail(403, '密码不正确，请重试。');
    }
    unset($access['login_failures'], $access['login_blocked_until']);
    startLogin($access); saveConfig($passwordPath, $access); reply(200, ['ok' => true]);
}
if ($action === 'logout') {
    unset($access['sessions'][hash('sha256', sessionToken())]);
    if ($configured) saveConfig($passwordPath, $access);
    setSessionCookie('', time() - 3600); reply(200, ['ok' => true]);
}
if (!authenticated($access)) fail(403, '登录已过期，请重新输入密码。');
$expiry = time() + ACCESS_DAYS * 86400;
$access['sessions'][hash('sha256', sessionToken())] = $expiry;
saveConfig($passwordPath, $access); setSessionCookie(sessionToken(), $expiry);
if ($action === 'write') {
    if (!isset($body['files']) || !is_array($body['files'])) fail(400, '验证文件格式无效。');
    placeFiles($documentRoot, $body['files']); reply(200, ['ok' => true, 'written' => count($body['files'])]);
}
if ($action === 'result') {
    $id = $body['id'] ?? ''; if (!is_string($id) || !isset($config['records'][$id])) fail(404, '没有找到这张证书。');
    environment($config['records'][$id]);
    reply(200, resultData($config['records'][$id], $root));
}
if ($action === 'pending') {
    $id = $body['id'] ?? ''; if (!is_string($id) || !isset($config['pending'][$id])) fail(404, '没有找到待验证的申请。');
    environment($config['pending'][$id]);
    reply(200, pendingData($config['pending'][$id]));
}
if (!$capable) fail(503, 'PHP 环境不能自动签发，请使用本地引导。');
$env = environment($body);
if (($body['termsAgreed'] ?? false) !== true) fail(400, '请先阅读并同意服务条款。');
if ($action === 'complete') {
    $id = $body['id'] ?? '';
    if (!is_string($id) || !isset($config['pending'][$id])) fail(404, '没有找到待验证的申请。');
    $pending = $config['pending'][$id]; $domainList = $pending['domains']; $env = $pending['environment'];
    $algorithm = $pending['keyAlgorithm']; $method = $pending['method']; $target = $pending['target']; $previous = $config['records'][$id] ?? null;
    if (($body['confirmed'] ?? false) !== true && count($pending['resources']) > 0) fail(400, '请先完成页面上的验证操作。');
} elseif ($action === 'renew') {
    $id = $body['id'] ?? '';
    if (!is_string($id) || !isset($config['records'][$id])) fail(404, '没有找到可续期的证书。');
    $previous = $config['records'][$id]; $domainList = $previous['domains']; $env = $previous['environment']; $algorithm = $previous['keyAlgorithm'];
    $method = $previous['method'] ?? 'http-01'; $target = $previous['target'] ?? 'site';
} else {
    if (!isset($body['domains']) || !is_array($body['domains'])) fail(400, '请填写域名。');
    $method = $body['method'] ?? 'http-01'; $target = $body['target'] ?? 'site';
    if (!in_array($method, ['http-01', 'dns-01'], true) || !in_array($target, ['site', 'other'], true)) fail(400, '申请方式无效。');
    $domainList = domains($body['domains'], $method); $algorithm = $body['keyAlgorithm'] ?? 'rsa-2048';
    if (!in_array($algorithm, ['rsa-2048', 'ec-p256'], true)) fail(400, '密钥类型无效。');
    $id = hash('sha256', $env . '|' . $algorithm . '|' . implode('|', $domainList)); $previous = $config['records'][$id] ?? null;
}
if ($env !== 'production') fail(400, '仅支持正式证书签发。');
// Repeated clicks before the renewal window return existing outputs, avoiding
// unnecessary orders. A new domain set always has a separate record.
if ($action !== 'complete' && $previous && time() < $previous['renewAt'] && time() < $previous['notAfter']) reply(200, resultData($previous, $root, true));
if ($action !== 'complete' && isset($config['pending'][$id]) && ($body['restart'] ?? false) !== true) reply(200, pendingData($config['pending'][$id]));
ignore_user_abort(true); @set_time_limit(240);
try {
    $ac = new AssistantACME($env);
    $currentTerms = $ac->getTermsURL();
    if (($body['termsUrl'] ?? '') !== $currentTerms) fail(409, '服务条款已更新，请重新检查连接并阅读条款。');
    $config['agreedTerms'][$env] = $currentTerms;
    if (!isset($config['accounts'][$env])) { $config['accounts'][$env] = $ac->generateRSAKey(2048); saveConfig($configPath, $config); }
    $ac->loadAccountKey($config['accounts'][$env]); $ac->register(true, []);
    if ($action === 'complete') {
        $privateKey = guardedRead($root . '/' . $pending['privateKeyFile']);
        $chain = $ac->finishManual($pending, $privateKey);
    } else {
    $privateKey = $algorithm === 'ec-p256' ? $ac->generateECKey('P-256') : $ac->generateRSAKey(2048);
    if ($target === 'other' || $method === 'dns-01') {
        $manual = $ac->beginManual($domainList, $method);
        $keyFile = 'ssl-private-key-' . substr($id, 0, 16) . '-' . bin2hex(random_bytes(6)) . '.php';
        guardedWrite($root . '/' . $keyFile, $privateKey . "\n");
        $pending = ['id' => $id, 'domains' => $domainList, 'environment' => $env, 'keyAlgorithm' => $algorithm,
            'method' => $method, 'target' => $target, 'privateKeyFile' => $keyFile] + $manual;
        $config['pending'][$id] = $pending; saveConfig($configPath, $config);
        if (count($pending['resources']) > 0) reply(200, pendingData($pending));
        $chain = $ac->finishManual($pending, $privateKey);
    } else {
    $settings = [];
    if ($previous) { try { $ari = $ac->getARI(guardedRead($root . '/' . $previous['certificateFile'])); $settings['replaces'] = $ari['ari_cert_id']; } catch (Throwable $error) { /* Official ARI optional; same-domain renewal remains supported. */ } }
    $domainConfig = array_fill_keys($domainList, ['challenge' => 'http-01']);
    $chain = $ac->getCertificateChain($privateKey, $domainConfig, static function ($options) use ($documentRoot) {
        if (!str_starts_with($options['key'], '/.well-known/acme-challenge/')) throw new RuntimeException('验证路径无效。');
        $created = placeFiles($documentRoot, [['name' => basename($options['key']), 'content' => $options['value']]]);
        return static function () use ($created) {
            foreach ($created as $path => $content) if (!is_link($path) && is_file($path) && @file_get_contents($path) === $content) @unlink($path);
        };
    }, $settings);
    }
    }
    $cert = openssl_x509_read($chain); $parsed = $cert ? openssl_x509_parse($cert) : false;
    if (!$cert || !$parsed || !openssl_x509_check_private_key($cert, $privateKey)) throw new RuntimeException('证书与私钥不匹配，已停止交付。');
    $sans = array_map('trim', explode(',', $parsed['extensions']['subjectAltName'] ?? ''));
    foreach ($domainList as $domain) if (!in_array('DNS:' . $domain, $sans, true)) throw new RuntimeException('证书没有覆盖所有域名，已停止交付。');
    $suffix = substr($id, 0, 16) . '-' . bin2hex(random_bytes(6));
    $certFile = 'ssl-certificate-' . $suffix . '.php'; $keyFile = 'ssl-private-key-' . $suffix . '.php';
    guardedWrite($root . '/' . $keyFile, $privateKey . "\n"); guardedWrite($root . '/' . $certFile, $chain);
    $before = (int) $parsed['validFrom_time_t']; $after = (int) $parsed['validTo_time_t'];
    $record = ['id' => $id, 'domains' => $domainList, 'environment' => $env, 'keyAlgorithm' => $algorithm, 'method' => $method, 'target' => $target,
        'notBefore' => $before, 'notAfter' => $after, 'renewAt' => (int) ($before + ($after - $before) * 2 / 3),
        'certificateFile' => $certFile, 'privateKeyFile' => $keyFile];
    try { $ari = $ac->getARI($chain); $record['renewAt'] = (int) (($ari['suggestedWindow']['start'] + $ari['suggestedWindow']['end']) / 2); } catch (Throwable $error) { /* Lifetime-based fallback. */ }
    $config['records'][$id] = $record; unset($config['pending'][$id]); saveConfig($configPath, $config);
    reply(200, resultData($record, $root));
} catch (AssistantInvalidOrder $error) {
    reply(422, ['ok' => false, 'invalidOrder' => true, 'message' => '本次验证未通过，请重新生成验证材料，并按页面指引上传文件或添加 DNS 记录。']);
} catch (\skoerfgen\ACMECert\ACME_Exception $error) {
    $type = $error->getType();
    $invalidOrder = $action === 'complete' && preg_match('/:(unauthorized|dns|connection|incorrectResponse)\z/', $type) === 1;
    reply(422, ['ok' => false, 'invalidOrder' => $invalidOrder, 'message' => '签发未完成：' . $error->getMessage() . '。请检查对应网站的文件或 DNS 验证；需要重试时按页面更新验证材料。']);
} catch (Throwable $error) {
    // Some upstream key errors include PEM in exception text: never expose them.
    fail(502, '证书还没有签发成功。请检查服务器网络和网站目录权限，再到“我的证书”查看进度。也可以在电脑上打开安装包里的 freessl.html，按提示申请。');
}

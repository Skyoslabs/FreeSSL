# 技术说明

## 目标与基本方案

同一安装包以 HTML 为入口。页面先探测同目录的 PHP，能用时由服务器签发；否则在安全上下文内使用浏览器签发，用户手动放置文件或添加 DNS。没有 PHP 的普通 HTTP 页面引导使用者在电脑上打开 HTML。

程序没有数据库、Composer 运行依赖、常驻 Node 服务或定时任务。只接入 Let’s Encrypt 正式 ACME v2；页面的一键续期由使用者点击触发。

## 官方路径与依赖选择

协议使用 [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html)，验证方式按 [Let’s Encrypt Challenge Types](https://letsencrypt.org/docs/challenge-types/)；续期参考官方 ARI。密钥和密码使用 PHP OpenSSL、`password_hash` / `password_verify`，浏览器使用 [Web Crypto](https://www.w3.org/TR/webcrypto/) 与 IndexedDB。

| 依赖 | 固定版本 / commit | 用途与许可 |
| --- | --- | --- |
| [fishballapp/acme](https://github.com/fishballapp/acme) | 0.18.0 / `71c94ff5810d6b148313a0714ecce03ea5f922bf` | 原生 fetch/Web Crypto 的浏览器 ACME，MIT |
| [skoerfgen/ACMECert](https://github.com/skoerfgen/ACMECert) | 3.7.3 / `6b4c54120851e88cf98fa380edbe9ed659e69e9f` | 无 Composer 运行依赖的 PHP ACME，HTTP callback 和 ARI，MIT |
| [fflate](https://github.com/101arrowz/fflate) | 0.8.3 | 浏览器与构建 ZIP，MIT |
| [esbuild](https://github.com/evanw/esbuild) | 0.28.2 | JavaScript 构建，MIT；不在网站运行 |
| [WordPress Playground](https://github.com/WordPress/wordpress-playground) | `@php-wasm/node` / `@php-wasm/universal` 3.1.56 | 真实 PHP 8.4 隔离测试，GPL-2.0-or-later；不进入安装包 |

npm lock 固定 registry 和 integrity。PHP 上游文件的 commit、SHA-256 和许可记录在 `vendor/acmecert/provenance.json`。运行库版权保留在构建程序中。

评估过 [acmephp/core](https://github.com/acmephp/core) 和 [node-acme-client](https://github.com/publishlab/node-acme-client)：前者的 Composer 依赖、后者的 Node 服务不适合两个程序文件的部署目标，没有采用。[acmejs](https://github.com/clshortfuse/acmejs) 未确认明确复用许可，没有纳入。浏览器存储直接使用标准 API，不增加存储服务或密码库。

## 签发流程

1. 读取官方 directory 与当前服务条款。
2. 创建或复用 ACME 账户，使用新证书私钥创建稳定 CSR 和订单。
3. 完成 HTTP-01 或 DNS-01。PHP 本站文件验证自动放置；其他网站文件验证和所有 DNS 验证由用户操作。
4. 等待验证和签发完成，核对证书公钥、私钥与全部 SAN 域名。
5. 保存配套 PEM / KEY 并返回网页，供使用者复制或下载。

HTTP-01 需要目标域名的公网 80 端口，验证 URL 固定为域名根路径下的 `.well-known/acme-challenge/`。DNS-01 支持泛域名，同名多条 TXT 必须同时保留。验证缓存仍有效时，可以直接完成订单。

## PHP 适配

上游传输默认跟随重定向，因此 `assistantFetchRaw` 和 `AssistantACME::http_request` 限定正式官方 HTTPS 目的地，拒绝非官方地址、额外端口和凭据，验证 TLS，设置超时并禁止重定向。JWS、nonce、CSR、订单与证书链逻辑继续复用上游。上游提供等价传输限制时可以替换这一层。

上游高层 callback 同步执行，无法跨请求等待手动文件/DNS 操作。`beginManual`、`finishManual` 和 `awaitManual` 按 RFC 8555 保存订单 URL、密钥与验证记录，下一次请求通过 POST-as-GET 恢复同一订单。该适配仅用于手动流程；没有私有主机面板接口。上游提供可恢复订单 API 时可以替换。

保存的 `method`、`target` 会带入后续验证和续期，用户主动选择本站 DNS 时也保留该选择。无效订单按页面指引重新生成，不静默改回文件验证。

## 登录和运行数据

首次进入设置自己的密码，未登录时申请和证书管理界面隐藏。PHP 使用 bcrypt cost 12，密码不明文保存。内部随机会话通过 HttpOnly / SameSite=Strict Cookie 传递，HTTPS 时设置 Secure；服务器有效期 30 天，登录轮换、退出撤销，最多 10 个有效会话，错误密码有短期限速。写操作检查同源。

| 文件 | 内容 |
| --- | --- |
| `freessl-password.php` | 密码哈希、登录会话和错误尝试计数 |
| `ssl-helper.config.php` | ACME 账户、证书元数据、待验证订单和条款记录 |
| `ssl-certificate-*.php` | 证书链 |
| `ssl-private-key-*.php` | 配套私钥 |
| `ssl-helper.lock.php` | 同一实例的操作锁 |

运行数据文件带 PHP 保护头，直接请求返回 404，权限为 0600；状态通过受保护随机临时文件原子替换。新签发保留旧密钥文件。网页只有登录后才返回并明文显示 PEM/KEY。

手动重置只删除 `freessl-password.php`，随后重新设置密码，账户、证书和待验证订单保留。旧版合并登录状态在同一锁内迁移一次并移除旧登录字段，没有公开的免登录重置 API。

停用 PHP 前，应先移走运行数据，避免服务器把 PHP 源码当静态文件返回。代码仓库和 Release 不包含任何运行数据。

## 根目录与子目录

PHP 程序目录的 realpath 必须位于服务器 `DOCUMENT_ROOT` 内。HTML 按自身地址连接同目录的 PHP；证书和状态留在程序目录，验证文件写入 `DOCUMENT_ROOT/.well-known/acme-challenge/`。

只接受固定 ACME 验证路径和格式正确的无后缀 token 文件。文件名、内容、数量、长度都校验，拒绝额外路径、符号链接、脚本和不同内容的同名文件。只清理本次创建且内容仍匹配的验证文件。网站根目录设置、权限和路由须与实际访问路径一致。

## 浏览器保存

本地记录使用 IndexedDB，每个页面路径单独保存。PBKDF2-SHA-256 使用随机 16 字节盐、600000 次迭代，AES-GCM 每次写入随机 12 字节 IV。登录后解密证书记录，密码不持久化。

忘记旧密码不能用新密码解密旧记录。复制 HTML 到新路径可以建立空白记录，原数据保留；更换浏览器、清理浏览器数据或移动页面会影响记录访问。

## 续期与安装

记录包含域名、算法、验证方式和实际证书有效期。尽量读取官方 ARI 建议窗口与 `replaces`；不可用时回退到证书寿命的 2/3。提前点击会返回现有证书，避免重复订单。

签发与安装分开：程序不自动修改主机面板或重载 Web 服务器。使用者安装新 PEM / KEY 后，网站才会使用新证书。

## 验证范围

- 浏览器核心：真实 RSA/ECDSA、JWS、CSR、SAN、泛域名多 TXT、badNonce、网络恢复、授权复用、无效 DNS、证书匹配与官方网络限制。
- PHP 8.4 / OpenSSL：首次设置/登录/退出、会话与文件保护、密码文件删除及旧状态迁移、跨来源拒绝、目录/符号链接限制、实际文件写入、自动/手动签发、续期和旧记录保留。
- 本机模拟 CA：独立验证签名与 CSR，生成配套 X.509；不会向公共 CA 注册测试账户。
- 构建与包：CSP、完整 DOM、许可、版本及三个文件的内容一致性。

已有 Chrome 本机界面复查覆盖 PHP 与浏览器模式、DNS 主动选择、固定申请状态、PEM/KEY 同页显示、手动文件方法、记录恢复、按域名续期和密码重置说明。

PHP 公网域名验证与证书签发已由使用者在实际网站验证通过。项目要求 PHP 8.1+，本地自动检查使用 PHP 8.4。

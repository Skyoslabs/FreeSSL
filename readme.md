<p align="center">
  <img src="assets/logo.svg" alt="Free SSL Logo" width="96" height="96">
</p>

<h1 align="center">Free SSL</h1>

通过网页申请和管理免费的 **Let’s Encrypt SSL 证书**，不用命令行。项目文件统一使用小写 `freessl` 命名。

当前版本：**v1.0.0** · [下载安装包](https://github.com/Skyoslabs/FreeSSL/releases/latest/download/freessl.zip) · [版本记录](changelog.md)

![自动检查](https://github.com/Skyoslabs/FreeSSL/actions/workflows/ci.yml/badge.svg)

## 开始使用

1. 下载并解压 `freessl.zip`。
2. 将 `freessl.html`、`freessl.php`、`readme.md` 上传到网站的同一个目录，打开 `freessl.html`。根目录、子目录都可以。
3. 首次进入自行设置密码，填写域名，选择文件或 DNS 验证，按页面提示申请。
4. 申请成功后，复制页面显示的证书 PEM 和私钥 KEY 到主机面板安装。

不支持 PHP 时，用 Chrome 在电脑上打开包里的 `freessl.html`，按提示上传文件或添加 DNS 记录。安装包只有这一份，HTML 始终是入口。

[完整使用说明](docs/usage.md)包含安装、子目录、手动创建验证文件、DNS、安装证书、续期、记录保存和忘记密码的处理方法；同一份说明也放在安装包中。

## 可以做什么

- 自动检测 PHP，能用时优先使用服务器签发。
- PHP 为本站申请时自动放好文件，一键完成文件验证和签发。
- 为其他网站申请证书，按提示完成文件或 DNS 验证；本站也可以主动选 DNS。
- 支持普通域名、泛域名、多域名，以及 RSA 2048 / ECDSA P-256。
- 按域名管理证书，自动保存 PEM 和 KEY，支持复制、下载和续期。
- 首次自设密码；PHP 忘记密码时，只删除自动生成的 `freessl-password.php`，重新打开页面设置新密码，证书和记录保留。

## 运行方式

| 使用方式 | 验证操作 | 记录保存 |
| --- | --- | --- |
| PHP 为本站申请 | 文件验证自动完成；DNS 按提示添加记录 | 程序所在目录 |
| PHP 为其他网站申请 | 上传文件或添加 DNS，未完成申请可继续 | 程序所在目录 |
| 电脑 HTML / 无 PHP 的 HTTPS 网站 | 上传文件或添加 DNS | 当前浏览器，使用密码加密 |

PHP 需要 8.1+、OpenSSL、cURL 或 `allow_url_fopen`，以及程序目录写入权限。自动文件验证还需要写入网站根目录下的 `.well-known/acme-challenge/`。程序放在子目录时，验证文件仍在网站根目录。没有 PHP 的普通 HTTP 页面会提示在电脑上打开 HTML。

续期从“我的证书”进入。PHP 本站文件验证会自动完成；手动文件或 DNS 验证需要按页面更新本次验证内容。证书签发后仍需安装到主机面板，续期后也要替换新的 PEM 和 KEY。

## 项目文档

- [使用说明](docs/usage.md)：面向使用者，不需要开发环境。
- [技术说明](docs/technical.md)：签发流程、存储、验证边界和依赖选型。
- [开发说明](docs/development.md)：构建、测试、目录结构和版本发布。
- [维护交接](docs/maintenance.md)：已确认的产品约定、开发基线与验证证据。
- [贡献说明](contributing.md)：提交问题和代码修改。
- [安全说明](security.md)：运行数据与漏洞报告。
- [版本记录](changelog.md)：每个版本的变化。

安装包只包含两个程序文件和使用说明。源代码、测试和技术文档在仓库中。

## 验证范围

自动检查使用真实 Web Crypto、PHP 8.4 / OpenSSL 和本机模拟 CA，验证签名、证书与私钥匹配、续期、密码重置、目录边界以及安装包一致性；不会向公共 CA 申请测试证书。

PHP 公网域名验证与证书签发已在实际网站验证通过。项目要求 PHP 8.1+，本地自动检查使用 PHP 8.4。[技术说明](docs/technical.md)记录了具体验证范围。

## 许可证

[MIT](LICENSE)。打包的上游运行库也采用 MIT，作者署名保留在源码和程序中。WordPress Playground 的 PHP 测试运行时采用 GPL-2.0-or-later，只用于开发，不进入安装包。

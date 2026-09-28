# 开发说明

## 环境

使用 Node.js 24.18+、npm 11.16+。这是固定的 PHP 测试运行时声明的最低版本；网站使用者不需要安装 Node.js、npm 或 Composer。

```sh
npm ci
npm run pack:install
npm run check
```

构建生成仓库根目录的 `freessl.html`、`freessl.php`，以及 `dist/freessl.zip`。安装包中的 `readme.md` 来自 `docs/usage.md`，不会包含仓库首页或技术文档。

## 目录

| 路径 | 内容 |
| --- | --- |
| `src/page.html`、`src/app.js` | 页面模板和操作流程 |
| `src/core.js` | 浏览器 ACME、密钥/CSR 与证书校验 |
| `src/online.js` | 同目录 PHP API，支持根目录和子目录 |
| `src/local.js` | 密码加密的浏览器记录 |
| `src/helper.php` | PHP 登录、保存、申请和续期 |
| `vendor/` | 固定版本的上游源码和许可证 |
| `tests/` | 浏览器密码学、真实 PHP 和安装包检查 |
| `docs/usage.md` | 安装包使用说明的唯一来源 |
| `docs/technical.md` | 技术方案与依赖记录 |
| `build.mjs`、`package.mjs` | 构建和打包 |

`src/page.html` 是模板，使用入口始终是构建后的 `freessl.html`。版本号以 `package.json` 为来源，构建时写入页面。

## 构建规则

JavaScript 依赖、PHP ACME 源码和运行库 MIT 许可嵌入两个程序文件。构建会重新计算内联脚本的 CSP SHA-256；替换打包脚本时使用函数，避免压缩代码中的特殊替换字符改变内容。

ZIP 固定包含 `freessl.html`、`freessl.php`、`readme.md` 三个小写 ASCII 文件名。时间戳固定，便于重复构建核对。`dist/` 不提交到 Git，正式安装包作为 GitHub Release 附件提供。

## 自动检查

```sh
npm test
npm run test:package
```

`npm test` 使用真实 Web Crypto、独立 JWS/CSR 校验、本机模拟 CA 和 WordPress 官方 PHP.wasm 8.4。PHP 测试替换网络传输只发生在隔离文件系统内，发布程序没有模拟传输入口。

`npm run test:package` 检查 CSP、DOM 绑定、许可证、版本信息、ZIP 文件名，以及 ZIP 内容与构建文件、使用说明的逐字节一致性。

GitHub Actions 在推送、Pull Request 或手动运行时安装依赖、构建同一安装包，再执行这些检查。Actions 使用官方仓库并固定到 commit；不配置线上主机凭据，也不向公共 CA 发起签发。

## 本机界面复查

```sh
node tests/preview.mjs
node tests/preview-test.mjs
node tests/preview-online.mjs
```

第一个服务显示实际构建页面。后两个显示明确标注的隔离模拟页面，使用随机临时登录和本机 CA；PHP 预览安装在子目录，并禁用浏览器 Web Crypto 来检查服务器签发路径。它们只用于开发，不能上传到网站。

## 版本更新与发布

1. 更新 `package.json` 和 `package-lock.json` 的版本，填写 `changelog.md`，同步仓库首页和使用说明中的版本。
2. 运行 `npm run pack:install` 和 `npm run check`，检查本次直接受影响的界面。
3. 检查待提交文件不含密码、Cookie、配置、私钥、证书包或真实运行数据，提交源码和构建文件。
4. 为确认的提交创建 `v版本号` 标签和 GitHub Release，只附上 `dist/freessl.zip`，在发布说明记录 SHA-256。

用户更新时，覆盖两个程序文件和使用说明即可。保留自动生成的运行文件；普通覆盖不会重置密码或删除已保存的证书。切勿把运行目录整体打包为源码发布。

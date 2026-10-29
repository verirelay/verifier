[English](README.md) | 简体中文

# Verifier

Verifier 是 VeriRelay 的本地参考验证工具，核对手上已有的证据，分别判断内容完整性、构建身份与 AMD 硬件可信性。

- [CLI 参考](docs/cli.zh-CN.md)：命令、选项、输入文件、报告字段与退出码
- [开发](docs/development.zh-CN.md)：检查、发布构建与测试
- [安全](SECURITY.md)：漏洞报告与安全范围

## 开始使用

从 [Releases](https://github.com/verirelay/verifier/releases) 下载对应平台的二进制，并用 `SHA256SUMS` 核对。

二进制未做代码签名，但每个 release 资产都带有 GitHub artifact attestation，可用 GitHub CLI 验证：

```sh
gh attestation verify verifier-linux-amd64 \
  --repo verirelay/verifier \
  --signer-workflow verirelay/verifier/.github/workflows/release.yml
```

```sh
chmod +x verifier-linux-amd64
./verifier-linux-amd64
```

- **macOS**：若下载的二进制被拦截，先运行 `xattr -d com.apple.quarantine verifier-darwin-arm64`。
- **从源码构建**：`make build` 后运行 `./dist/verifier`。

默认命令在随机 loopback 端口启动内嵌网页并打开浏览器。

网页 URL 含有每次运行随机生成的访问 token：请勿分享，使用后关闭 Verifier。

文件留在本机。只有 Registry 查询与 AMD KDS 证书和 CRL 请求会访问网络。

## 准备文件

- 通过 `/v1/avr/evidence/<request_id>` 获得的收据证据包：签名收据，加上启动时归档的证明报告。
- 精确的请求和响应 body 文件，或原文留存（Raw Capture）的加密原文及 Store-Id 和 Store-Key。也可以直接粘贴完整的响应 header 行。

CLI 根据文件名中的 `request` 与 `response` 识别 body 文件。空文件是有效的空 body。

## 命令行

```sh
verifier check evidence.json request.bin response.bin
verifier check evidence.json capture.json --store-id "$STORE_ID" --store-key "$STORE_KEY"
verifier check evidence.json request.bin response.bin --offline --json
verifier check evidence.json request.bin response.bin --bootstrap bootstrap.json
verifier --offline
verifier -h
```

二进制内固定了独立于 Registry 的受信任 Release Key。

`--release-key` 用另行确认可信的公钥替换它。其他公钥签名的构建记录会被忽略。

## 读懂结果

- **内容**：收据签名有效，body 与收据中的 SHA-256 一致。这是相对于该收据的完整性，不单独证明收据由真实的 VeriRelay 签发。
- **代码**：经过认证的启动度量匹配签名构建记录，其受信任 Release Key 的签名在本机核对，且 Registry 未将其标为已撤销。
- **硬件**：核对以下各项：
  - VCEK、ASK 与独立可信的 AMD 根
  - 证明报告签名
  - 当前 CRL
  - TCB 一致性
  - VMPL
  - 安全策略
  - `REPORT_DATA` 密钥绑定

  禁止调试、迁移代理与 CXL。未配置最低固件安全公告基线。

  归档的证明响应披露引导文件时，`HOST_DATA` 必须等于其 SHA-256，报告会显示该引导文件的 VeriProv 地址、profile 与 VeriProv 身份密钥。`--bootstrap` 还要求 `HOST_DATA` 等于你预期的引导文件的 SHA-256。

只有证据与某项检查相矛盾时结论才是失败。无法读取的输入，例如无法解密的原文留存或不支持的格式，结论为无法判断。

- `--offline` 不访问网络，代码结论为无法判断。
- 使用 `--offline`、`--no-crl` 或无法获取 AMD CRL 时，硬件撤销状态未知，硬件结论为无法判断。
- 缺少归档的证明报告时，硬件与代码结论均为无法判断。

AMD 的 ARK 签名 CRL 撤销的是 ASK 中间证书，不逐一撤销 VCEK。

## 验证边界

- 收据覆盖 body，不覆盖 HTTP header、trailer 或传输分帧。
- 上游 TLS SPKI 是收据中的签名事实，并非新的在线 TLS 观测。
- 归档证据能证明密钥绑定，不能证明当前在线状态或可信历史时间。
- Registry 当前未撤销的响应不是签名的历史非撤销证明。

请同时阅读三项结论。

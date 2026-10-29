[English](cli.md) | 简体中文

# CLI 参考

## 命令

- `verifier [options]` 打开本地内嵌网页。
- `verifier version` 输出版本。
- `verifier -h` 输出帮助。

```text
verifier check FILE... [options]
```

`check` 的选项可放在文件前后。`--` 表示后续均为文件名。

以下选项同时适用于网页与 `check`：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `--registry URL` | `https://registry.verirelay.com` | Registry 地址 |
| `--release-key KEY` | 独立固定的公钥 | 受信任的 Release Key，即无 padding base64url 编码的原始 Ed25519 公钥 |
| `--offline` | 关闭 | 不访问网络，代码与硬件无法判断 |
| `--no-crl` | 关闭 | 跳过 AMD CRL，硬件无法判断 |

- `--registry` 须为 HTTPS 地址，loopback 地址可用 HTTP。不跟随重定向。
- `--release-key` 替换固定公钥。重复该选项可信任多个。

以下选项只适用于 `check`：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `--store-id VALUE` | 空 | Store-Id 或粘贴的 header 行 |
| `--store-key VALUE` | 空 | Store-Key 或粘贴的 header 行 |
| `--bootstrap FILE` | 无 | 预期的引导文件，`HOST_DATA` 必须等于其 SHA-256 |
| `--json` | 关闭 | 输出 JSON 而非可读文本 |

## 输入文件

| 输入 | 识别方式 |
| --- | --- |
| 收据证据包（必填） | JSON 结构 |
| 原文留存的加密文件 | JSON 结构 |
| 请求 body | 文件名包含 `request` 或 `请求` |
| 响应 body | 文件名包含 `response` 或 `响应` |
| Store-Id 与 Store-Key | 含 Store-Key header 行的文本文件 |

未识别或重复类型是用法错误。提供 body 文件时优先使用 body 文件，不使用原文留存。

收据证据包与原文留存按 [`avr/1` 收据](https://github.com/verirelay/protocol/blob/main/docs/avr1.zh-CN.md)的「解码」一节解码。

## 报告

`--json` 输出与网页导出使用 `verifier-report/1`：

| 字段 | 内容 |
| --- | --- |
| `version` | `verifier-report/1` |
| `generated_at` | RFC 3339 UTC 生成时间 |
| `content`, `code`, `hardware` | 内容、代码与硬件三项结论 |
| `receipt` | 收据事实，收据有效时提供：`request_id`、`method`、`upstream_host`、`path`、`status`、`time`、`upstream_tls_spki` |
| `release` | 匹配的构建身份，代码结论通过时提供：`repository`、`tag`、`commit` |
| `bootstrap` | `HOST_DATA` 绑定的引导文件，由证明响应披露或由 `--bootstrap` 提供时给出：`url`、`profile`（未设置时为空）、`identity_public_key` |
| `limitations` | 验证边界，为 `code` 与 `message` 列表 |

每项结论包含以下字段：

| 字段 | 内容 |
| --- | --- |
| `status` | `pass`、`fail` 或 `unable` |
| `code` | 稳定代码 |
| `reason` | 英文原因 |
| `details` | 各项检查，为 `code` 与 `message` 列表 |

`status` 的取值：

- `pass`
- 证据与某项检查相矛盾时为 `fail`
- 检查无法完成时为 `unable`，包括无法读取的输入

报告不包含 body 或 Store-Key。

## Release Key 与引导文件的结论

| 情况 | 结论 | 代码 |
| --- | --- | --- |
| 构建记录的 `proof.key_id` 不是受信任的 Release Key | 跳过 | |
| 该启动度量没有由受信任 Release Key 签名的构建记录 | 代码无法判断 | `release_key_untrusted` |
| 受信任 Release Key 下的构建记录或撤销声明签名无效 | 代码失败 | `build_record_invalid`, `revocation_invalid` |
| `HOST_DATA` 不是所披露 `bootstrap` 的 SHA-256 | 硬件失败 | `bootstrap_mismatch` |
| `HOST_DATA` 不是 `--bootstrap` 文件的 SHA-256 | 硬件失败 | `bootstrap_unexpected` |
| `--bootstrap` 文件不是有效的引导文件 | 硬件无法判断 | `bootstrap_invalid` |

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 三项结论全部通过 |
| `1` | 存在失败，优先于其他情况 |
| `2` | 存在无法判断，或用法、文件读写及输出错误 |

[概览](../README.zh-CN.md)

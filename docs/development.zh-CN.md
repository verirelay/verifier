[English](development.md) | 简体中文

# 开发

## 检查

```sh
go run mvdan.cc/gofumpt@v0.12.0 -w .
go vet ./...
go test ./...
make build
golangci-lint run
actionlint
```

CI 使用 golangci-lint v2.15.0 与 actionlint v1.7.12。

网页是内嵌的 `internal/webui/index.html`。

| 目标 | 作用 |
| --- | --- |
| `make build` | 构建 `dist/verifier` |
| `make check` | 运行测试、构建与 lint |
| `make release VERSION=<tag>` | 交叉编译发布二进制与 `SHA256SUMS` 到 `dist/release` |

推送 `v*` tag 时，release workflow 会：

1. 运行 `make release`
2. 为 `dist/release` 中的每个资产生成 GitHub artifact attestation
3. 发布 GitHub Release

## 包接口

`pkg/verifier` 让 Go 程序执行与 CLI 相同的验证。参见[包文档](https://pkg.go.dev/github.com/verirelay/verifier/pkg/verifier)。

## 测试

`internal/testdata` 中的 fixture 是由 VeriRelay 生成的合成证据。[internal/testdata/README.md](../internal/testdata/README.md) 列出各文件及重新生成方法。

CLI 通过的 golden 文件由报告的 golden 文件打印而来。经审查后按以下顺序更新报告与 CLI 的 golden 文件：

```sh
UPDATE_GOLDEN=1 go test ./pkg/verifier
UPDATE_GOLDEN=1 go test ./internal/cli
```

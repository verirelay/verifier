.PHONY: build release test lint check clean

DIST_DIR := dist
VERIFIER := $(DIST_DIR)/verifier
VERSION ?= dev
RELEASE_PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

build:
	mkdir -p $(DIST_DIR)
	go build -o $(VERIFIER) ./cmd/verifier

release:
	rm -rf $(DIST_DIR)/release
	mkdir -p $(DIST_DIR)/release
	set -e; for platform in $(RELEASE_PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; ext=; \
		if [ "$$os" = windows ]; then ext=.exe; fi; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o $(DIST_DIR)/release/verifier-$$os-$$arch$$ext ./cmd/verifier; \
	done
	cd $(DIST_DIR)/release && sha256sum verifier-* > SHA256SUMS

test:
	go test ./...

lint:
	golangci-lint run

check: test build lint

clean:
	rm -rf $(DIST_DIR)

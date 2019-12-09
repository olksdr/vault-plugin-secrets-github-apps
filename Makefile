LDFLAGS := -s -w
GOFILES := $(shell find . -name "*.go")
.DEFAULT_GOAL := build

vault-plugin-secrets-github-apps: $(GOFILES)
	@ go build -ldflags="$(LDFLAGS)"

.PHONY: fmt
fmt: 
	@ go mod tidy
	@ go fmt ./...

.PHONY: build
build: generate fmt vault-plugin-secrets-github-apps

.PHONY: clean
clean:
	@ rm -r vault-plugin-secrets-github-apps || true


.PHONY: slim
slim: build
	@ upx vault-plugin-secrets-github-apps

.PHONY: generate
generate:
	@ go generate $(go list ./... | grep -v /vendor/)

.PHONY: test
test:
	@ go test -v ./...

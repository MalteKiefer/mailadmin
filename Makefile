# mailadmin — build & quality targets.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
LDFLAGS := -s -w -X mailadmin/internal/cli.Version=$(VERSION)
GOOS    ?= linux
GOARCH  ?= amd64

.PHONY: build build-linux install fmt vet test race check staticcheck gosec vulncheck lint clean

## build: build for the host platform into ./mailadmin
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o mailadmin ./cmd/mailadmin

## build-linux: static, stripped linux binary (matches the release artifact)
build-linux:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath \
		-ldflags "$(LDFLAGS)" -o dist/mailadmin-$(GOOS)-$(GOARCH) ./cmd/mailadmin

## install: install to /usr/local/sbin (root)
install: build-linux
	install -m 0755 dist/mailadmin-$(GOOS)-$(GOARCH) /usr/local/sbin/mailadmin

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...

gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## check: run the full quality gate (matches CI + docs/REQUIREMENTS.md)
check: fmt vet race staticcheck gosec vulncheck
	@echo "all checks passed"

clean:
	rm -rf dist mailadmin

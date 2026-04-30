BINARY := faultline
MODULE := github.com/faultline-go/faultline
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DIST_DIR := dist
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT) -X $(MODULE)/internal/version.BuildDate=$(DATE)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build build-all checksums sbom sign-checksums release-dry-run test lint fmt scan-testdata clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/faultline

build-all:
	rm -rf $(DIST_DIR)
	mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		out="$(DIST_DIR)/$(BINARY)_$${os}_$${arch}$${ext}"; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" ./cmd/faultline || exit 1; \
	done

checksums: build-all
	cd $(DIST_DIR) && if command -v sha256sum >/dev/null 2>&1; then find . -maxdepth 1 -type f ! -name 'checksums.txt' ! -name '*.sig' ! -name '*.pem' -print0 | sort -z | xargs -0 sha256sum > checksums.txt; else find . -maxdepth 1 -type f ! -name 'checksums.txt' ! -name '*.sig' ! -name '*.pem' -print0 | sort -z | xargs -0 shasum -a 256 > checksums.txt; fi

sbom:
	@command -v syft >/dev/null 2>&1 || { echo "syft is required for SBOM generation: https://github.com/anchore/syft"; exit 1; }
	@set -e; found=0; for artifact in $(DIST_DIR)/*.tar.gz $(DIST_DIR)/*.zip; do \
		if [ ! -e "$$artifact" ]; then continue; fi; \
		found=1; \
		echo "generating SBOM for $$artifact"; \
		syft "$$artifact" -o spdx-json="$$artifact.spdx.json"; \
	done; \
	if [ "$$found" -eq 0 ]; then echo "no release archives found in $(DIST_DIR)"; exit 1; fi

sign-checksums:
	@test -f $(DIST_DIR)/checksums.txt || { echo "$(DIST_DIR)/checksums.txt not found; run make checksums first"; exit 1; }
	@command -v cosign >/dev/null 2>&1 || { echo "cosign is required for signing: https://docs.sigstore.dev/cosign/installation/"; exit 1; }
	cosign sign-blob --yes --output-signature $(DIST_DIR)/checksums.txt.sig --output-certificate $(DIST_DIR)/checksums.txt.pem $(DIST_DIR)/checksums.txt

release-dry-run:
	goreleaser release --snapshot --clean

test:
	go test ./...

lint:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*' -not -path './third_party/*')

scan-testdata: build
	cd testdata/simple-go-module && ../../bin/$(BINARY) scan ./... --format html --out ../../faultline-testdata-report.html --verbose

clean:
	rm -rf bin dist faultline-report.html faultline-testdata-report.html faultline-pr.sarif review.md

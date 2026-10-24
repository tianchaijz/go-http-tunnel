GO ?= go
GOFMT ?= $(shell $(GO) env GOROOT)/bin/gofmt
OUTPUT_DIR = build
PLATFORMS ?= darwin/amd64 darwin/arm64 freebsd/386 freebsd/amd64 freebsd/arm linux/386 linux/amd64 linux/arm linux/arm64 windows/386 windows/amd64
GIT_COMMIT = $(shell git describe --always)

.PHONY: all clean fmt check .check-fmt .check-vet .check-mod test get-deps get-tools build build-cross release package publish
all: check test build

clean:
	@test -n "$(OUTPUT_DIR)" && test "$(abspath $(OUTPUT_DIR))" != /
	rm -rf -- "$(OUTPUT_DIR)/pkg" "$(OUTPUT_DIR)/dist"
	rm -f -- "$(OUTPUT_DIR)/tunnel" "$(OUTPUT_DIR)/tunneld" "$(OUTPUT_DIR)/tunnel.exe" "$(OUTPUT_DIR)/tunneld.exe"

fmt:
	$(GO) fmt ./...

check: .check-fmt .check-vet .check-mod

.check-fmt:
	@set -e; files=$$("$(GOFMT)" -l $$(git ls-files '*.go')); \
	if [ -n "$$files" ]; then printf 'Run make fmt to format:\n%s\n' "$$files"; exit 1; fi

.check-vet:
	$(GO) vet ./...

.check-mod:
	$(GO) mod verify

test:
	$(GO) test -cover -race ./...

get-deps:
	$(GO) mod download

get-tools:
	$(GO) version

build:
	mkdir -p "$(OUTPUT_DIR)"
	CGO_ENABLED=0 $(GO) build -ldflags "-w -X main.version=$(GIT_COMMIT)" -o "$(OUTPUT_DIR)/" ./cmd/tunnel ./cmd/tunneld

build-cross:
	@set -e; for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		mkdir -p "$(OUTPUT_DIR)/pkg/$${os}_$$arch"; \
		CGO_ENABLED=0 GOARM=5 GOOS=$$os GOARCH=$$arch $(GO) build \
			-ldflags "-w -X main.version=$(GIT_COMMIT)" \
			-o "$(OUTPUT_DIR)/pkg/$${os}_$$arch/" ./cmd/tunnel ./cmd/tunneld; \
	done

release:
	$(MAKE) check
	$(MAKE) test
	$(MAKE) clean
	$(MAKE) build-cross
	$(MAKE) package

package:
	mkdir -p "$(OUTPUT_DIR)/dist"
	@set -e; cd "$(OUTPUT_DIR)/pkg"; \
	for osarch in *; do \
		ext=; case "$$osarch" in windows_*) ext=.exe;; esac; \
		for binary in tunnel tunneld; do \
			if [ ! -s "$$osarch/$$binary$$ext" ]; then \
				printf 'Incomplete platform build: %s/%s%s\n' "$$osarch" "$$binary" "$$ext" >&2; exit 1; \
			fi; \
		done; \
	done; \
	for osarch in *; do \
		tar -czf "../dist/tunnel_$$osarch.tar.gz" -C "$$osarch" .; \
	done
	cd "$(OUTPUT_DIR)/dist" && sha256sum tunnel_*.tar.gz > SHA256SUMS

publish:
	ghr -recreate -u mmatczuk -t ${GITHUB_TOKEN} -r go-http-tunnel pre-release ${OUTPUT_DIR}/dist

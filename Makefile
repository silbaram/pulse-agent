GO ?= go
GOOS ?= linux
GOARCH ?= amd64
CGO_ENABLED ?= 0
BUILD_DIR ?= dist
BINARY ?= $(BUILD_DIR)/pulse-agent-linux-$(GOARCH)

GO_BUILD_FLAGS := -mod=readonly -trimpath -buildvcs=false
GO_LDFLAGS := -s -w -buildid=

.PHONY: build-linux reproducible-linux test

build-linux:
	mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GO_BUILD_FLAGS) -ldflags='$(GO_LDFLAGS)' -o "$(BINARY)" ./cmd/pulse-agent

reproducible-linux:
	$(MAKE) build-linux BINARY=$(BUILD_DIR)/pulse-agent.reproducible.1
	$(MAKE) build-linux BINARY=$(BUILD_DIR)/pulse-agent.reproducible.2
	cmp $(BUILD_DIR)/pulse-agent.reproducible.1 $(BUILD_DIR)/pulse-agent.reproducible.2

test:
	$(GO) test ./...

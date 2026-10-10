# secrets-broker build. `make build` produces everything sb install expects in bin/.
BIN := bin
GO_CMDS := secrets-broker-mcp sb sb-browser-proxy sb-cdpfill

.PHONY: build go swift test clean

build: go swift

go:
	@mkdir -p $(BIN)
	@for c in $(GO_CMDS); do echo "go build $$c"; go build -o $(BIN)/$$c ./cmd/$$c; done

# Swift approval helpers are macOS-only; skipped elsewhere (isolated-mode
# approval then fails closed — see docs/security.md).
swift:
	@if [ "$$(uname)" = "Darwin" ] && command -v swiftc >/dev/null 2>&1; then \
		for c in sb-approve sb-seauth; do echo "swiftc $$c"; \
			swiftc -O -o $(BIN)/$$c cmd/$$c/main.swift; done; \
	else echo "skipping Swift helpers (not macOS or no swiftc)"; fi

test:
	go test ./...

clean:
	rm -rf $(BIN)

#!/bin/bash
# Run bitwarden adapter tests inside node:22-slim + mounted Go tarball.
set -e
if [ -f /tmp/go.tgz ] && ! command -v go >/dev/null; then
  tar -C /usr/local -xzf /tmp/go.tgz
fi
export PATH=$PATH:/usr/local/go/bin
command -v bw >/dev/null || npm install -g @bitwarden/cli >/dev/null 2>&1
export NODE_EXTRA_CA_CERTS=/certs/cert.pem
export BITWARDENCLI_APPDATA_DIR=/data
go version
bw --version
go test ./internal/adapters/bitwarden/ -v

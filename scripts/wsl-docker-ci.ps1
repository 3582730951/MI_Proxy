$ErrorActionPreference = "Stop"

$workspaceWindows = (Get-Location).Path
$workspaceWsl = (wsl -d Ubuntu -- bash -lc "wslpath -a '$workspaceWindows'").Trim()

if (-not $workspaceWsl) {
  throw "Unable to resolve WSL workspace path"
}

$script = @"
set -euo pipefail
cd '$workspaceWsl'
docker run --rm \
  -v '${workspaceWsl}:/workspace' \
  -w /workspace \
  ubuntu:22.04 \
  bash -lc '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates golang-go git make
    git config --global --add safe.directory /workspace
    mkdir -p dist
    export CGO_ENABLED=0
    go version
    sh -n scripts/install.sh
    sh -n scripts/update.sh
    go test ./...
    go run ./cmd/security-scan
    go run ./cmd/license-scan > dist/license-scan.container.json
    go run ./cmd/iac-scan > dist/iac-scan.container.json
    make security-scan
    make license-scan
    make iac-scan
    make rule-test
    make e2e
    go run ./cmd/load-smoke > dist/load-smoke.container.json
    go run ./cmd/dast-smoke > dist/dast-smoke.container.json
    go run ./cmd/api-fuzz > dist/api-fuzz.container.json
    go run ./cmd/chaos-smoke > dist/chaos-smoke.container.json
    go run ./cmd/sbom > dist/sbom.container.json
    go run ./cmd/acceptance > dist/acceptance-container.json
    go run ./cmd/provenance dist/sbom.container.json dist/license-scan.container.json dist/iac-scan.container.json dist/acceptance-container.json > dist/provenance.container.json
  '
"@

wsl -d Ubuntu -u root -- bash -lc $script

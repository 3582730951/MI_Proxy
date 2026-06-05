$ErrorActionPreference = "Stop"
go test ./...
go run ./cmd/security-scan
New-Item -ItemType Directory -Force -Path dist | Out-Null
go run ./cmd/license-scan > dist/license-scan.local.json
go run ./cmd/iac-scan > dist/iac-scan.local.json
corepack pnpm test
corepack pnpm lint
corepack pnpm typecheck
go run ./cmd/load-smoke > dist/load-smoke.local.json
go run ./cmd/dast-smoke > dist/dast-smoke.local.json
go run ./cmd/api-fuzz > dist/api-fuzz.local.json
go run ./cmd/chaos-smoke > dist/chaos-smoke.local.json
go run ./cmd/sbom > dist/sbom.json
go run ./cmd/acceptance > dist/acceptance-local.json
go run ./cmd/provenance dist/sbom.json dist/license-scan.local.json dist/iac-scan.local.json dist/acceptance-local.json > dist/provenance.local.json

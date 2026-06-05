package main

import (
	"encoding/json"
	"os"
	"time"
)

type item struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
}

func main() {
	report := map[string]any{
		"generatedAt": time.Now().UTC(),
		"note":        "This report lists local and WSL Docker Ubuntu 22.04 evidence. Long-running production gates such as 30-minute 2,000 RPS load, full ZAP, toxiproxy DB/Redis chaos, human review, cosign release signing, and 24h canary still require external or long-duration evidence.",
		"items": []item{
			{Category: "environment", Name: "cmd -> WSL -> Ubuntu -> Docker ubuntu:22.04 zero-dependency validation", Status: "container-smoke-passed", Evidence: "./scripts/wsl-docker-ci.ps1"},
			{Category: "rules", Name: "CN direct, private IP direct, WARP include, Google Scholar exclude, subscription conversion/rule source/webhook SSRF validation, source checksum validation, bounded large-rule coverage/hit-rate estimates, canary rollout, conflict blocking, and diff hit-change reports", Status: "container-test-passed", Evidence: "go test ./packages/rulecompiler ./services/controlplane"},
			{Category: "control-plane", Name: "nodes, RBAC, ABAC by region/tag/environment, kernel tuning status, protocol inbound stats, route decision trace audit, subscription context/rules/split-DNS/cache/compression, node-scoped config deployment payloads, capacity tier and autoscaling recommendations, WARP WireGuard config import/health/cooldown/recovery and scheduling modes, Argo tunnel config rendering plus Cloudflare API automation plan, config rollback, BBR+ target IP cache, Agent credential rotation", Status: "container-test-passed", Evidence: "go test ./services/controlplane"},
			{Category: "security", Name: "API token scopes/IP allowlist, node ABAC, Agent mTLS fingerprint auth, sensitive-operation confirmation, encrypted WARP keys, subscription access audit, security waiver owner/expiry/remediation enforcement, audit hash chain", Status: "container-test-passed", Evidence: "services/controlplane/controlplane_test.go; services/controlplane/api_test.go"},
			{Category: "security", Name: "OIDC config validation, JWT alg/kid hardening, secure rotating session cookies, Passkey/WebAuthn challenge verification, TOTP verification, strict CSP/security headers, CORS whitelist, CSRF protection, TLS 1.3 gateway config, login/config/agent registration rate limits", Status: "container-test-passed", Evidence: "services/controlplane/auth_test.go; services/controlplane/api_test.go; cmd/dast-smoke"},
			{Category: "api", Name: "draft API endpoints for nodes, rules including POST domain test, webhook endpoints, subscriptions and conversion jobs, WARP profile import/probe/disable, protocol stats, in-memory node metrics write/query, logs, audit, alerts, security waivers, incidents, and P0/P1/P2/P3 runbook catalog", Status: "container-test-passed", Evidence: "services/controlplane/api_test.go"},
			{Category: "agent", Name: "low resource mode, BBR probe, structured sysctl/rlimit tuning plan, UDP protection, systemd watchdog, config rollback, local ring-buffer logs", Status: "container-test-passed", Evidence: "go test ./agent"},
			{Category: "ui", Name: "Chinese account/password operations dashboard, safe VPS runtime panel, default subscription metadata, required navigation/metrics, capacity/autoscaling/cost signals, and route decision audit drill-down", Status: "container-test-passed", Evidence: "go test ./apps/web"},
			{Category: "deploy", Name: "Dockerfile, docker-compose without default DB or panel admin password, localhost-bound service ports, one-command bootstrapper, zero-interaction VPS install script with runtime passwd.txt password file, generated default subscription token kept out of the frontend, safe auto-update script with configurable password file, health check, and rollback, PostgreSQL schema and indexes", Status: "container-test-passed", Evidence: "go test ./tests; Dockerfile; docker-compose.yml; migrations/001_core.sql; scripts/bootstrap.sh; scripts/install.sh; scripts/update.sh"},
			{Category: "performance", Name: "1000 node heartbeat, 2000 subscription render smoke, and 100k rule publish under 10s local regression", Status: "container-smoke-passed", Evidence: "dist/load-smoke.container.json; services/controlplane/controlplane_test.go"},
			{Category: "security", Name: "local DAST smoke and API fuzz smoke", Status: "container-smoke-passed", Evidence: "dist/dast-smoke.container.json; dist/api-fuzz.container.json"},
			{Category: "security-tools", Name: "CodeQL, Semgrep, Gitleaks, TruffleHog, Trivy, Grype, OSV/Syft, Checkov, tfsec, KICS, ZAP, Schemathesis, RESTler, FOSSA/ScanCode, k6, toxiproxy configs, local dependency license policy scan, and local IaC policy scan", Status: "config-present-container-tested", Evidence: ".github/workflows; .semgrep.yml; .gitleaks.toml; zap.yaml; schemathesis.toml; tests/load; tests/chaos; cmd/license-scan; cmd/iac-scan"},
			{Category: "stability", Name: "node offline, Postgres/Redis dependency degradation, 100k rule publish without blocking subscriptions/API, WARP 50% failure, P0/P1/P2/P3 runbook catalog and rollback/pause/exit-switch/subscription-limit actions, agent rollback, memory pressure smoke", Status: "container-smoke-passed", Evidence: "dist/chaos-smoke.container.json; services/controlplane/controlplane_test.go"},
			{Category: "security", Name: "local secret scan, allowlisted structured command execution enforcement, and incompatible dependency license blocking", Status: "container-tool-passed", Evidence: "go run ./cmd/security-scan; go run ./cmd/license-scan; internal/safeexec"},
			{Category: "release", Name: "SBOM, license/IaC scan evidence, local provenance, release gate, cosign/SLSA/canary workflow", Status: "config-present-container-tested", Evidence: "dist/sbom.container.json; dist/license-scan.container.json; dist/iac-scan.container.json; dist/provenance.container.json; scripts/release-gate.ps1; .github/workflows/release.yml"},
			{Category: "external", Name: "protected main, full security tools including FOSSA/ScanCode, staging DAST, full load, toxiproxy chaos, human/GPT-5.5 review, cosign, 24h canary", Status: "requires-external-or-long-duration-evidence", Evidence: "GitHub/staging/release/canary records"},
		},
		"complete": false,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		panic(err)
	}
}

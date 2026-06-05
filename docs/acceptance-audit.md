# Acceptance audit

This file tracks `docs/plan.md` evidence. The current code covers a local and WSL Docker Ubuntu 22.04 executable slice, but the whole plan is not fully complete because several required gates need real CI, staging, release, human review, or long-duration evidence.

## Container evidence available
- Required test path: `cmd -> wsl -> Ubuntu -> docker run ubuntu:22.04`.
- Command: `./scripts/wsl-docker-ci.ps1`.
- Container starts from `ubuntu:22.04`, installs `ca-certificates golang-go git make`, sets `CGO_ENABLED=0`, then runs tests and smoke gates.
- Generated evidence:
  - `dist/load-smoke.container.json`
  - `dist/dast-smoke.container.json`
  - `dist/api-fuzz.container.json`
  - `dist/chaos-smoke.container.json`
  - `dist/license-scan.container.json`
  - `dist/iac-scan.container.json`
  - `dist/sbom.container.json`
  - `dist/provenance.container.json`
  - `dist/acceptance-container.json`

## Local and container evidence available
- Rule classification: `go test ./packages/rulecompiler`
- CN direct, CN IP/private direct, WARP include, Google Scholar exclude: `tests/rules/domain-classification`
- Rule conflict blocking, bounded large-rule coverage analysis, hit-rate estimates, canary rollout percentages, and diff reports with added, removed, changed, conflict, and hit-change sections: `packages/rulecompiler`, `services/controlplane`
- 100k rule compile/publish regression keeps subscription rendering and domain-test API reads progressing, with the active policy replaced only after conflict checks and report generation complete: `services/controlplane`
- Rule set source registration validates public HTTPS source URLs, blocks localhost/private/link-local SSRF targets, rejects URL userinfo/query/fragment secrets, and requires sha256 checksums: `services/controlplane`
- Webhook endpoint registration validates public HTTPS callback URLs, blocks localhost/private/link-local SSRF targets, rejects URL userinfo/query/fragment secrets, requires confirmation, and hashes signing secrets without returning them: `services/controlplane`
- Node registry, heartbeat, offline alert, idempotent dangerous task recovery: `services/controlplane`
- Node registration and heartbeat collect kernel tuning values for BBR/qdisc, nofile, somaxconn, tcp_fastopen, and port range; the kernel tuning API reports per-node compliance and issues through node ABAC: `services/controlplane`
- Agent heartbeat accepts and normalizes inbound protocol stats for VLESS, VMess, Hysteria2, TUIC, and Trojan; protocol stats are copied on node reads and aggregated through a node-ABAC-filtered API: `services/controlplane`
- Route decision trace audit records sanitized input, outbound, matched rule, source, rule type, and reason for UI transparency: `services/controlplane`
- RBAC, tenant isolation, node ABAC by tenant/region/tag/environment, subscription token hash/revoke, token-free subscription access audit logging: `services/controlplane`
- Subscription conversion jobs validate public HTTPS source URLs, block localhost/private/link-local SSRF targets, reject URL userinfo/query/fragment secrets, require sha256 source checksums, require confirmation, and do not fetch remote content inside the control plane: `services/controlplane`
- API token scope/IP allowlist, sensitive-operation confirmation, encrypted WARP private keys, and audit hash-chain verification: `services/controlplane`
- Security waivers require a named owner, future expiration, remediation plan, confirmation, sanitized text, and audit-chain records: `services/controlplane`
- Agent mTLS fingerprint credential rotation, hashed fingerprint storage, heartbeat-only scope, and scoped token denial on node writes: `services/controlplane`
- OIDC config validation, JWT `alg`/`kid` hardening, secure rotating session-cookie flags, Passkey/WebAuthn challenge verification, TOTP, strict CSP/security headers, CORS whitelist, CSRF protection, and TLS 1.3 gateway config: `services/controlplane/auth.go`, `services/controlplane/api.go`, `cmd/dast-smoke`
- Rate limits for login attempts, subscription rendering, config deployment, and Agent registration: `services/controlplane/controlplane.go`, `services/controlplane/api.go`
- Config publish failure preservation, rollback, node-scoped deployment payload rendering with only global plus target-node blocks, pause-release runbook blocking, P0/P1/P2/P3 runbook catalog, and operational runbooks for credential-rotation-required flags, node deployment pause, rollback, exit switch, WARP disable, subscription cache, subscription emergency limit, and P3 triage: `services/controlplane`
- WARP source compliance, standard WireGuard config import without helper scripts, encrypted imported PrivateKey storage, DNS/HTTP/WireGuard health checks, cooldown and recovery probes, least-latency, least-error, weighted-round-robin, sticky-by-domain, sticky-by-user scheduling, and 50% failure survivability: `services/controlplane`
- Argo tunnel metadata registration, sanitized cloudflared ingress config rendering, and token-free Cloudflare API tunnel/configuration/DNS automation plans without Cloudflare API tokens or URL userinfo: `services/controlplane`
- Dependency health degradation for Postgres and Redis recovery windows: `services/controlplane`
- Node metric samples are accepted through an authenticated metrics write path, retained in an in-memory time-series buffer instead of PostgreSQL, filtered by tenant/node ABAC, and exposed through metrics query APIs for Overview aggregation: `services/controlplane`
- Capacity planning maps node and connection pressure to Small/Medium/Large tiers, target subscription/API RPS, recommended API replicas, autoscaling actions, and cost-aware routing actions through an authenticated metrics API: `services/controlplane`
- Alert API lists tenant/node-ABAC-filtered alerts with secret-redacted and HTML-escaped messages; alert acknowledgement requires confirmation and appends an audit-chain record: `services/controlplane`
- BBR+ connection scheduling uses client IP, VPS public IP, resource pressure, target classification, and target IP cache: `services/controlplane/connection_scheduler.go`
- API draft endpoints for nodes, rules including `POST /api/v1/rules/test-domain`, webhook endpoint registration, subscriptions and conversion jobs, WARP, node metrics write/query, overview metrics, logs, audit logs, alerts, security waivers, incidents, P0/P1/P2/P3 runbook catalog, and runbook execution, including node ABAC request claims: `services/controlplane/api.go`
- Subscription generation by user, device, region, protocol, outbound policy, embedded CN/private direct rules, Google Scholar WARP exclusion, split DNS strategy, token kinds, IP allowlist, one-time revocation, ETag / Last-Modified, gzip, and brotli support: `services/controlplane/controlplane.go`, `services/controlplane/api_test.go`
- Agent low-resource mode, BBR/sysctl model, structured sysctl/rlimit tuning plan for nofile, somaxconn, tcp_fastopen, and ip_local_port_range, UDP protection limits, systemd watchdog heartbeat model, config diff apply and rollback: `agent`
- Agent local ring buffer and error-log drain for exception-only reporting: `agent`
- UI navigation, core metrics visualization, capacity/autoscaling/cost signals, route decision audit drill-down, and dark dashboard style based on `example/imager_1.png`: `apps/web/index.html`
- Docker deployment, non-root runtime image, Compose deployment without default database password, localhost-bound service ports, one-command bootstrapper, zero-interaction VPS installer with generated password file defaulting to runtime `passwd.txt`, and auto-update script with configurable password file, fast-forward pull, health check, and rollback: `Dockerfile`, `docker-compose.yml`, `scripts/bootstrap.sh`, `scripts/install.sh`, `scripts/update.sh`
- PostgreSQL core model and indexes: `migrations/001_core.sql`
- Local security scan: `go run ./cmd/security-scan`
- Local dependency license policy scan blocks unknown external dependency licenses and incompatible licenses before release evidence is accepted: `go run ./cmd/license-scan`
- Local IaC policy scan blocks Compose default weak passwords, non-local service port bindings, unpinned or `latest` images, and root runtime containers before release evidence is accepted: `go run ./cmd/iac-scan`
- Local SBOM includes first-party components, Go module dependencies, license IDs, and a root dependency relation: `go run ./cmd/sbom`
- Dynamic port fallback: `cmd/control-plane/main.go`
- DAST/API fuzz/chaos/load smoke: `cmd/dast-smoke`, `cmd/api-fuzz`, `cmd/chaos-smoke`, `cmd/load-smoke`
- Allowlisted structured command execution for provenance git commands, with security scan blocking raw command execution elsewhere: `internal/safeexec`, `cmd/security-scan`
- Security and testing tool configs/hooks: `.github/workflows/codeql.yml`, `.semgrep.yml`, `.gitleaks.toml`, TruffleHog, Trivy, Grype, OSV, Checkov, tfsec, KICS, ZAP, Schemathesis, RESTler, FOSSA/ScanCode optional CI hooks, `zap.yaml`, `schemathesis.toml`, `api/openapi.yaml`, `tests/load`, `tests/chaos`
- Release gate config for license/IaC scan evidence, cosign, SLSA provenance, canary, human review, GPT-5.5 review, and external evidence checks; local provenance must include license and IaC scan evidence: `.github/workflows/release.yml`, `scripts/release-gate.ps1`, `docs/release-gates.md`

## External evidence still missing
- Protected main branch. The repository has `origin`, but branch protection cannot be proven from local files.
- Real CI execution with CodeQL, Semgrep, Gitleaks, Trivy, Grype, Syft, ZAP, API fuzzing, FOSSA/ScanCode license scan, and IaC scan.
- Container image and image scan.
- Staging deployment for full DAST and load tests.
- k6/wrk/vegeta full SLO evidence for 2,000 RPS sustained 30-minute peak tests.
- DB, Redis, Agent, and WARP chaos tests against a deployed environment. Local Postgres/Redis degradation modeling exists, but toxiproxy evidence against deployed dependencies is still missing.
- Human review, security owner approval, and GPT-5.5 architecture/security review records.
- cosign-signed release artifact, SLSA provenance, and 24-hour canary evidence. The workflow and gate are configured, but no production release record is present locally.

## Current status
The repository is not ready to claim full `docs/plan.md` completion. A containerized implementation slice and smoke gates are in place; external release, security, stability, and governance gates remain unproven.

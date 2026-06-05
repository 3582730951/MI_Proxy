package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentAndDatabaseArtifactsExist(t *testing.T) {
	root := findRepoRoot(t)
	required := []string{
		".github/workflows/ci.yml",
		".github/workflows/codeql.yml",
		".github/workflows/release.yml",
		".gitleaks.toml",
		".semgrep.yml",
		"cmd/iac-scan/main.go",
		"cmd/license-scan/main.go",
		"Dockerfile",
		"api/openapi.yaml",
		"docker-compose.yml",
		"docs/release-gates.md",
		"internal/safeexec/safeexec.go",
		"migrations/001_core.sql",
		"README.md",
		"schemathesis.toml",
		"scripts/bootstrap.sh",
		"scripts/install.sh",
		"scripts/update.sh",
		"scripts/release-gate.ps1",
		"scripts/wsl-docker-ci.ps1",
		"tests/chaos/docker-compose.toxiproxy.yml",
		"tests/load/subscription-smoke.js",
		"tests/load/full-2000rps-30m.js",
		"zap.yaml",
	}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("missing required artifact %s: %v", rel, err)
		}
	}

	schema := read(t, filepath.Join(root, "migrations/001_core.sql"))
	for _, table := range []string{
		"users", "tenants", "nodes", "node_metrics", "configs", "config_deployments",
		"rules", "rule_sets", "subscriptions", "warp_profiles", "warp_probe_results",
		"audit_logs", "incidents",
	} {
		if !strings.Contains(schema, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("schema missing table %s", table)
		}
	}
	for _, index := range []string{"node_id", "tenant_id", "version", "created_at"} {
		if !strings.Contains(schema, index) {
			t.Fatalf("schema missing required index dimension %s", index)
		}
	}

	dockerfile := read(t, filepath.Join(root, "Dockerfile"))
	if !strings.Contains(dockerfile, "CGO_ENABLED=0") || !strings.Contains(dockerfile, "ubuntu:22.04") {
		t.Fatalf("Dockerfile must build static binaries and run on Ubuntu 22.04")
	}
	if !strings.Contains(dockerfile, "USER 10001:10001") {
		t.Fatal("Dockerfile runtime must drop root privileges")
	}

	compose := read(t, filepath.Join(root, "docker-compose.yml"))
	if strings.Contains(compose, "sing_box_next_"+"dev") {
		t.Fatal("docker-compose must not contain a hardcoded database password")
	}
	for _, required := range []string{
		"${POSTGRES_PASSWORD:?",
		"${HOST:-127.0.0.1}:${PORT:-8080}:8080",
		"${POSTGRES_BIND:-127.0.0.1}:5432:5432",
		"${REDIS_BIND:-127.0.0.1}:6379:6379",
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("docker-compose missing secure default %s", required)
		}
	}

	readme := read(t, filepath.Join(root, "README.md"))
	for _, required := range []string{
		"MI Proxy VPS",
		"tmp=$(mktemp)",
		"Downloading bootstrap script",
		"curl -fL --retry 3",
		"wget -O \"$tmp\"",
		"test -s \"$tmp\"",
		"scripts/bootstrap.sh",
		"GitHub bootstrap 默认监听",
		"旧版本",
		"自动升级",
		"0.0.0.0:8080",
		"http://<VPS_PUBLIC_IP>:8080",
		"ufw allow 8080/tcp",
		"sh \"$tmp\"",
		"sh \"$tmp\" -l",
		"--passwd-file",
		"passwd.txt",
		"sing-box-next-panel-update.timer",
		"scripts/update.sh",
		"/healthz",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("README missing copy-paste deployment guidance %s", required)
		}
	}

	bootstrapScript := read(t, filepath.Join(root, "scripts/bootstrap.sh"))
	installScript := read(t, filepath.Join(root, "scripts/install.sh"))
	updateScript := read(t, filepath.Join(root, "scripts/update.sh"))
	for _, required := range []string{
		"one-command VPS installs",
		"starting $PROJECT_NAME bootstrap",
		"defaults to public HTTP",
		"BIND_CONFIGURED",
		"load_existing_metadata_for_bootstrap",
		"apply_metadata_default",
		"install.env",
		"install_git_if_missing",
		"DEBIAN_FRONTEND=noninteractive",
		"git clone --depth 1",
		"mktemp -d",
		"scripts/install.sh",
		"--public",
		"MI_PANEL_REPO_URL",
		"MI_PANEL_BRANCH",
		"MI_PANEL_INSTALL_DIR",
		"--passwd-file",
		"PASSWD_FILE",
	} {
		if !strings.Contains(bootstrapScript, required) {
			t.Fatalf("bootstrap script missing one-command deployment feature %s", required)
		}
	}
	if strings.Contains(readme, "wget -qO") || strings.Contains(readme, "curl -fsSLo") {
		t.Fatal("README bootstrap command must print download failures instead of using quiet fetch flags")
	}
	for _, required := range []string{
		"--dry-run",
		"--skip-deps",
		"--no-systemd",
		"--public",
		"--local",
		"--file",
		"--passwd-file",
		"HOST_CONFIGURED",
		"PORT_CONFIGURED",
		"PREVIOUS_REVISION",
		"rollback_to_previous_revision",
		"git clone",
		"docker compose",
		"docker-compose",
		"POSTGRES_PASSWORD",
		"PASSWD_FILE",
		"passwd.txt",
		"EnvironmentFile=$PASSWD_FILE",
		"systemd",
		"update.timer",
		"AUTO_UPDATE",
		"/healthz",
	} {
		if !strings.Contains(installScript, required) {
			t.Fatalf("install script missing zero-interaction deployment feature %s", required)
		}
	}
	for _, required := range []string{
		"pull --ff-only",
		"--restart-only",
		"--passwd-file",
		"PASSWD_FILE",
		"passwd.txt",
		"LOCK_DIR",
		"/healthz",
		"rollback_to",
		"--remove-orphans",
	} {
		if !strings.Contains(updateScript, required) {
			t.Fatalf("update script missing auto-update feature %s", required)
		}
	}
	if strings.Contains(installScript, "printf 'POSTGRES_PASSWORD=%s\\n' \"$current_secret\"\n  } > \"$tmp\"\n  mv \"$tmp\" \"$ENV_FILE\"") {
		t.Fatal("install script must not write generated passwords to .env; use passwd.txt/PASSWD_FILE")
	}
	for _, forbidden := range []string{"read -p", "curl | bash", "curl | sh", "| bash", "| sh"} {
		if strings.Contains(bootstrapScript, forbidden) || strings.Contains(installScript, forbidden) || strings.Contains(updateScript, forbidden) {
			t.Fatalf("bootstrap/install/update scripts must stay noninteractive and avoid pipe-to-shell pattern %s", forbidden)
		}
	}

	ci := read(t, filepath.Join(root, ".github/workflows/ci.yml"))
	if strings.Contains(ci, "pull-requests: write") {
		t.Fatal("CI workflow must not request unused pull-request write permission")
	}
	for _, required := range []string{"go test ./...", "cmd/security-scan", "cmd/license-scan", "cmd/iac-scan", "cmd/load-smoke", "cmd/dast-smoke", "cmd/api-fuzz", "cmd/chaos-smoke", "checkov", "tfsec", "kics", "grype", "trufflehog", "scancode", "fossa", "RESTler", "schemathesis.toml", "zap.yaml"} {
		if !strings.Contains(ci, required) {
			t.Fatalf("CI config missing %s", required)
		}
	}

	release := read(t, filepath.Join(root, ".github/workflows/release.yml"))
	for _, required := range []string{"release-gate.ps1", "cosign sign", "attest-build-provenance", "CANARY_24H_PASSED", "TOXIPROXY_CHAOS_EVIDENCE"} {
		if !strings.Contains(release, required) {
			t.Fatalf("release config missing %s", required)
		}
	}

	gate := read(t, filepath.Join(root, "scripts/release-gate.ps1"))
	for _, required := range []string{"licenseScan", "iacScan", "provenanceIncludesLicenseScan", "provenanceIncludesIaCScan", "MAIN_BRANCH_PROTECTED", "HUMAN_REVIEW_APPROVED", "GPT55_REVIEW_APPROVED", "COSIGN_SIGNATURE_REF", "SLSA_PROVENANCE_REF"} {
		if !strings.Contains(gate, required) {
			t.Fatalf("release gate missing %s", required)
		}
	}

	runbooks := read(t, filepath.Join(root, "docs/runbooks.md"))
	for _, required := range []string{"P0", "P1", "P2", "P3", "Pause", "Rate limit", "Roll back", "WARP", "Restart Agents"} {
		if !strings.Contains(runbooks, required) {
			t.Fatalf("runbooks missing %s coverage", required)
		}
	}

	load := read(t, filepath.Join(root, "tests/load/full-2000rps-30m.js"))
	if !strings.Contains(load, "rate: 2000") || !strings.Contains(load, `duration: "30m"`) {
		t.Fatal("full load test must encode 2,000 RPS for 30 minutes")
	}

	openapi := read(t, filepath.Join(root, "api/openapi.yaml"))
	for _, endpoint := range []string{
		"/api/v1/auth/passkeys/register-options",
		"/api/v1/auth/passkeys/authenticate",
		"/api/v1/nodes/register",
		"/api/v1/nodes",
		"/api/v1/nodes/{id}",
		"/api/v1/nodes/kernel-tuning",
		"/api/v1/nodes/{id}/agent-credential",
		"/api/v1/nodes/{id}/heartbeat",
		"/api/v1/nodes/{id}/deploy-config",
		"/api/v1/nodes/{id}/rollback",
		"/api/v1/rules",
		"/api/v1/rules/compile",
		"/api/v1/rules/test-domain",
		"/api/v1/rules/publish",
		"/api/v1/rules/rollback",
		"/api/v1/rules/rule-sets",
		"/api/v1/webhooks/endpoints",
		"/api/v1/routes/trace",
		"/api/v1/routes/traces",
		"/api/v1/subscriptions",
		"/api/v1/subscriptions/conversions",
		"/api/v1/subscriptions/{id}/revoke",
		"/api/v1/warp/profiles",
		"/api/v1/warp/profiles/import-wireguard",
		"/api/v1/warp/profiles/{id}/probe",
		"/api/v1/warp/profiles/{id}/disable",
		"/api/v1/argo/tunnels",
		"/api/v1/argo/cloudflare/automation-plan",
		"/api/v1/argo/tunnels/{id}/config",
		"/api/v1/protocols/stats",
		"/api/v1/metrics/nodes/{id}",
		"/api/v1/metrics/overview",
		"/api/v1/metrics/capacity",
		"/api/v1/metrics/dependencies",
		"/api/v1/logs",
		"/api/v1/audit-logs",
		"/api/v1/alerts",
		"/api/v1/alerts/{id}/ack",
		"/api/v1/security/waivers",
		"/api/v1/incidents",
		"/api/v1/incidents/runbooks",
		"/api/v1/incidents/{id}/runbook/{name}",
		"/sub/{token}/{client_type}",
	} {
		if !strings.Contains(openapi, endpoint) {
			t.Fatalf("OpenAPI spec missing %s", endpoint)
		}
	}
	for _, field := range []string{"deviceId", "region", "protocol", "outboundPolicy"} {
		if !strings.Contains(openapi, field) {
			t.Fatalf("OpenAPI spec missing subscription context field %s", field)
		}
	}
	if !strings.Contains(openapi, "rolloutPercent") || !strings.Contains(openapi, "process_name") || !strings.Contains(openapi, "protocol") {
		t.Fatal("OpenAPI spec must document rule rollout and advanced rule dimensions")
	}
	if strings.Count(openapi, `"429"`) < 3 {
		t.Fatal("OpenAPI spec must document rate-limit responses")
	}
	if !strings.Contains(openapi, "gzip") || !strings.Contains(openapi, "brotli") {
		t.Fatal("OpenAPI spec must document subscription gzip and brotli support")
	}
	if !openAPIPathBlockContains(openapi, "/api/v1/rules/test-domain:", "post:") {
		t.Fatal("OpenAPI spec must document POST /api/v1/rules/test-domain")
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "docs", "plan.md")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatal("repo root not found")
		}
		dir = next
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func openAPIPathBlockContains(openapi, path, needle string) bool {
	start := strings.Index(openapi, path)
	if start < 0 {
		return false
	}
	rest := openapi[start+len(path):]
	next := strings.Index(rest, "\n  /")
	if next >= 0 {
		rest = rest[:next]
	}
	return strings.Contains(rest, needle)
}

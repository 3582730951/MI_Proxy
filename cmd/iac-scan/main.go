package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type finding struct {
	File     string `json:"file"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

type report struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Passed      bool      `json:"passed"`
	Mode        string    `json:"mode"`
	Findings    []finding `json:"findings"`
}

var sha256DigestPattern = regexp.MustCompile(`@sha256:[0-9a-fA-F]{64}$`)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	report := scan(root, time.Now().UTC())
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "iac scan failed: %v\n", err)
		os.Exit(2)
	}
	if !report.Passed {
		os.Exit(1)
	}
}

func scan(root string, generatedAt time.Time) report {
	report := report{
		GeneratedAt: generatedAt,
		Passed:      true,
		Mode:        "local-iac-policy-scan",
		Findings:    []finding{},
	}
	report.checkDockerfile(filepath.Join(root, "Dockerfile"))
	report.checkCompose(filepath.Join(root, "docker-compose.yml"), true)
	report.checkCompose(filepath.Join(root, "tests", "chaos", "docker-compose.toxiproxy.yml"), false)
	report.Passed = len(report.Findings) == 0
	return report
}

func (r *report) checkDockerfile(path string) {
	content, ok := r.read(path)
	if !ok {
		return
	}
	r.reject(path, "dockerfile-no-latest", content, ":latest", "container base images must not use the latest tag")
	r.require(path, "dockerfile-ubuntu-2204-runtime", content, "FROM ubuntu:22.04", "runtime image must remain the Ubuntu 22.04 validation target")
	r.requireDockerfileImageDigests(path, content)
	r.require(path, "dockerfile-apt-cache-clean", content, "rm -rf /var/lib/apt/lists/*", "apt package lists must be removed after install")
	r.require(path, "dockerfile-non-root-final-user", content, "USER 10001:10001", "runtime container must drop root privileges")
}

func (r *report) checkCompose(path string, requireControlPlaneBind bool) {
	content, ok := r.read(path)
	if !ok {
		return
	}
	r.reject(path, "compose-no-latest", content, ":latest", "compose images must not use the latest tag")
	r.requireComposeImageDigests(path, content)
	r.reject(path, "compose-no-hardcoded-db-password", content, "sing_box_next_"+"dev", "compose files must not contain a hardcoded database password")
	r.require(path, "compose-requires-db-password", content, "${POSTGRES_PASSWORD:?", "compose must require an injected database password")
	r.require(path, "compose-postgres-localhost", content, "${POSTGRES_BIND:-127.0.0.1}:5432:5432", "Postgres must bind to localhost by default")
	r.require(path, "compose-redis-localhost", content, "${REDIS_BIND:-127.0.0.1}:6379:6379", "Redis must bind to localhost by default")
	if requireControlPlaneBind {
		r.require(path, "compose-control-plane-localhost", content, "${HOST:-127.0.0.1}:${PORT:-8080}:8080", "control plane must bind to localhost by default")
	}
}

func (r *report) requireDockerfileImageDigests(path, content string) {
	for lineNo, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		image := ""
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "--") {
				continue
			}
			image = field
			break
		}
		if image == "" || sha256DigestPattern.MatchString(image) {
			continue
		}
		r.add(path, "dockerfile-image-digest-pinned", "high", fmt.Sprintf("Dockerfile FROM image on line %d must be pinned with @sha256 digest", lineNo+1))
	}
}

func (r *report) requireComposeImageDigests(path, content string) {
	for lineNo, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "image:") {
			continue
		}
		image := strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
		image = strings.Trim(image, `"'`)
		if image == "" || sha256DigestPattern.MatchString(image) {
			continue
		}
		r.add(path, "compose-image-digest-pinned", "high", fmt.Sprintf("Compose image on line %d must be pinned with @sha256 digest", lineNo+1))
	}
}

func (r *report) read(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		r.add(path, "iac-file-present", "high", "required IaC artifact is missing or unreadable")
		return "", false
	}
	return string(data), true
}

func (r *report) require(path, rule, content, needle, message string) {
	if !strings.Contains(content, needle) {
		r.add(path, rule, "high", message)
	}
}

func (r *report) reject(path, rule, content, needle, message string) {
	if strings.Contains(content, needle) {
		r.add(path, rule, "high", message)
	}
}

func (r *report) add(path, rule, severity, message string) {
	r.Findings = append(r.Findings, finding{
		File:     filepath.ToSlash(path),
		Rule:     rule,
		Severity: severity,
		Message:  message,
	})
}

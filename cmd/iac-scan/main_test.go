package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIaCScanPassesSecureArtifacts(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "Dockerfile", secureDockerfile())
	writeFixture(t, root, "docker-compose.yml", secureCompose(true))
	writeFixture(t, root, filepath.Join("tests", "chaos", "docker-compose.toxiproxy.yml"), secureCompose(false))

	report := scan(root, time.Unix(0, 0).UTC())
	if !report.Passed {
		t.Fatalf("secure fixtures should pass: %+v", report.Findings)
	}
}

func TestIaCScanBlocksHardcodedComposePassword(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "Dockerfile", secureDockerfile())
	writeFixture(t, root, "docker-compose.yml", secureCompose(true)+"\nPOSTGRES_PASSWORD: sing_box_next_"+"dev\n")
	writeFixture(t, root, filepath.Join("tests", "chaos", "docker-compose.toxiproxy.yml"), secureCompose(false))

	report := scan(root, time.Unix(0, 0).UTC())
	if report.Passed || !hasRule(report, "compose-no-hardcoded-db-password") {
		t.Fatalf("hardcoded compose password should fail: %+v", report.Findings)
	}
}

func TestIaCScanRequiresNonRootDockerfileUser(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "Dockerfile", "FROM ubuntu:22.04\nRUN rm -rf /var/lib/apt/lists/*\n")
	writeFixture(t, root, "docker-compose.yml", secureCompose(true))
	writeFixture(t, root, filepath.Join("tests", "chaos", "docker-compose.toxiproxy.yml"), secureCompose(false))

	report := scan(root, time.Unix(0, 0).UTC())
	if report.Passed || !hasRule(report, "dockerfile-non-root-final-user") {
		t.Fatalf("root Docker runtime should fail: %+v", report.Findings)
	}
}

func TestIaCScanRequiresDockerfileImageDigests(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "Dockerfile", "FROM ubuntu:22.04\nRUN apt-get update && rm -rf /var/lib/apt/lists/*\nUSER 10001:10001\n")
	writeFixture(t, root, "docker-compose.yml", secureCompose(true))
	writeFixture(t, root, filepath.Join("tests", "chaos", "docker-compose.toxiproxy.yml"), secureCompose(false))

	report := scan(root, time.Unix(0, 0).UTC())
	if report.Passed || !hasRule(report, "dockerfile-image-digest-pinned") {
		t.Fatalf("unpinned Dockerfile image should fail: %+v", report.Findings)
	}
}

func TestIaCScanRequiresComposeImageDigests(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "Dockerfile", secureDockerfile())
	writeFixture(t, root, "docker-compose.yml", strings.Replace(secureCompose(true), "postgres:16-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "postgres:16-alpine", 1))
	writeFixture(t, root, filepath.Join("tests", "chaos", "docker-compose.toxiproxy.yml"), secureCompose(false))

	report := scan(root, time.Unix(0, 0).UTC())
	if report.Passed || !hasRule(report, "compose-image-digest-pinned") {
		t.Fatalf("unpinned compose image should fail: %+v", report.Findings)
	}
}

func writeFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func secureDockerfile() string {
	return "FROM ubuntu:22.04@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nRUN apt-get update && rm -rf /var/lib/apt/lists/*\nUSER 10001:10001\n"
}

func secureCompose(withControlPlane bool) string {
	content := "services:\n  postgres:\n    image: postgres:16-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set password}\n    ports:\n      - \"${POSTGRES_BIND:-127.0.0.1}:5432:5432\"\n  redis:\n    image: redis:7-alpine@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n    ports:\n      - \"${REDIS_BIND:-127.0.0.1}:6379:6379\"\n"
	if withControlPlane {
		content += "  control-plane:\n    ports:\n      - \"${HOST:-127.0.0.1}:${PORT:-8080}:8080\"\n"
	}
	return content
}

func hasRule(report report, rule string) bool {
	for _, finding := range report.Findings {
		if finding.Rule == rule {
			return true
		}
	}
	return false
}

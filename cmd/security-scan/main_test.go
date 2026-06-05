package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanBlocksRawCommandExecution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unsafe.go")
	rawCall := "exec." + "Command(\"git\")"
	if err := os.WriteFile(path, []byte("package unsafe\nfunc run(){ "+rawCall+" }\n"), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	findings, err := scan(path)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, finding := range findings {
		if finding.pattern == "raw-command-execution" {
			return
		}
	}
	t.Fatalf("raw command execution was not flagged: %+v", findings)
}

func TestAllowlistedCommandExecutorExemptionIsNarrow(t *testing.T) {
	rawCall := "exec." + "CommandContext"
	if !isAllowlistedCommandExecutor("internal/safeexec/safeexec.go", "cmd := "+rawCall+"(ctx, spec.Name)") {
		t.Fatal("safeexec command context should be exempt")
	}
	if isAllowlistedCommandExecutor("cmd/provenance/main.go", "cmd := "+rawCall+"(ctx, spec.Name)") {
		t.Fatal("non-safeexec command context should not be exempt")
	}
}

func TestScanBlocksWeakYAMLPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	key := "POSTGRES_" + "PASSWORD"
	line := key + ": weak_dev_password"
	if err := os.WriteFile(path, []byte("services:\n  db:\n    environment:\n      "+line+"\n"), 0600); err != nil {
		t.Fatalf("write temp compose: %v", err)
	}
	findings, err := scan(path)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, finding := range findings {
		if finding.pattern == "weak-password-yaml" {
			return
		}
	}
	t.Fatalf("weak YAML password was not flagged: %+v", findings)
}

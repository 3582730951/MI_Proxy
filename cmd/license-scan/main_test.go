package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLicenseScanAllowsKnownReviewedDependency(t *testing.T) {
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(goMod, []byte(`module test

go 1.18

require github.com/andybalholm/brotli v1.1.1
`), 0600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	report, err := scanGoMod(goMod, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("scan go.mod: %v", err)
	}
	if !report.Passed {
		t.Fatalf("expected known dependency to pass, findings: %+v", report.Findings)
	}
	if !hasComponent(report, "github.com/andybalholm/brotli", "MIT", "allowed") {
		t.Fatalf("expected brotli MIT component, got %+v", report.Components)
	}
}

func TestLicenseScanBlocksUnknownDependency(t *testing.T) {
	report := evaluateRequirements([]moduleRequirement{
		{Path: "example.com/unreviewed", Version: "v0.1.0"},
	}, map[string]string{}, time.Unix(0, 0).UTC())

	if report.Passed {
		t.Fatal("expected unknown dependency license to block")
	}
	if !hasComponent(report, "example.com/unreviewed", "UNKNOWN", "blocked") {
		t.Fatalf("expected blocked unknown component, got %+v", report.Components)
	}
	if len(report.Findings) != 1 || report.Findings[0].Severity != "blocking" {
		t.Fatalf("expected one blocking finding, got %+v", report.Findings)
	}
}

func TestLicenseScanBlocksForbiddenLicense(t *testing.T) {
	report := evaluateRequirements([]moduleRequirement{
		{Path: "example.com/forbidden", Version: "v1.0.0"},
	}, map[string]string{
		"example.com/forbidden": "AGPL-3.0-only",
	}, time.Unix(0, 0).UTC())

	if report.Passed {
		t.Fatal("expected forbidden license to block")
	}
	if !hasComponent(report, "example.com/forbidden", "AGPL-3.0-only", "blocked") {
		t.Fatalf("expected blocked forbidden component, got %+v", report.Components)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %+v", report.Findings)
	}
}

func TestParseGoModRequirementsHandlesBlockAndInlineRequire(t *testing.T) {
	requirements := parseGoModRequirements(`module test

go 1.18

require example.com/inline v1.0.0

require (
	example.com/block-a v1.2.3
	example.com/block-b v2.0.0 // indirect
)
`)

	if len(requirements) != 3 {
		t.Fatalf("expected three requirements, got %+v", requirements)
	}
	for _, want := range []string{"example.com/inline", "example.com/block-a", "example.com/block-b"} {
		if !hasRequirement(requirements, want) {
			t.Fatalf("missing requirement %s in %+v", want, requirements)
		}
	}
}

func hasComponent(report licenseReport, name, license, status string) bool {
	for _, component := range report.Components {
		if component.Name == name && component.License == license && component.Status == status {
			return true
		}
	}
	return false
}

func hasRequirement(requirements []moduleRequirement, path string) bool {
	for _, requirement := range requirements {
		if requirement.Path == path {
			return true
		}
	}
	return false
}

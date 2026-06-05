package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildSBOMIncludesGoModuleDependenciesAndLicenses(t *testing.T) {
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(goMod, []byte(`module test

go 1.18

require github.com/andybalholm/brotli v1.1.1
`), 0600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	doc, err := buildSBOM(goMod)
	if err != nil {
		t.Fatalf("build sbom: %v", err)
	}
	if !hasSBOMComponent(doc, "github.com/andybalholm/brotli", "go-module", "v1.1.1", "MIT") {
		t.Fatalf("expected brotli Go module with MIT license, got %+v", doc.Components)
	}
	if !rootDependsOn(doc, "pkg:golang/github.com/andybalholm/brotli@v1.1.1") {
		t.Fatalf("expected root dependency relation to include brotli, got %+v", doc.Dependencies)
	}
}

func TestBuildSBOMMarksUnreviewedDependencyLicenseUnknown(t *testing.T) {
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(goMod, []byte(`module test

go 1.18

require example.com/unreviewed v0.1.0
`), 0600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	doc, err := buildSBOM(goMod)
	if err != nil {
		t.Fatalf("build sbom: %v", err)
	}
	if !hasSBOMComponent(doc, "example.com/unreviewed", "go-module", "v0.1.0", "UNKNOWN") {
		t.Fatalf("expected unreviewed module license to be UNKNOWN, got %+v", doc.Components)
	}
}

func hasSBOMComponent(doc sbom, name, componentType, version, license string) bool {
	for _, component := range doc.Components {
		if component.Name == name && component.Type == componentType && component.Version == version && component.License == license {
			return true
		}
	}
	return false
}

func rootDependsOn(doc sbom, bomRef string) bool {
	for _, dependency := range doc.Dependencies {
		if dependency.Ref != "pkg:local/sing-box-next-panel" {
			continue
		}
		for _, item := range dependency.DependsOn {
			if item == bomRef {
				return true
			}
		}
	}
	return false
}

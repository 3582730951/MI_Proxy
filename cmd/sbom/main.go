package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

type sbom struct {
	Name         string       `json:"name"`
	Type         string       `json:"type"`
	Generated    time.Time    `json:"generated"`
	GoVersion    string       `json:"goVersion"`
	Components   []component  `json:"components"`
	Dependencies []dependency `json:"dependencies"`
}

type component struct {
	BOMRef  string `json:"bomRef,omitempty"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
	License string `json:"license,omitempty"`
}

type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type moduleRequirement struct {
	Path    string
	Version string
}

var reviewedDependencyLicenses = map[string]string{
	"github.com/andybalholm/brotli": "MIT",
}

func main() {
	doc, err := buildSBOM("go.mod")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom generation failed: %v\n", err)
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		panic(err)
	}
}

func buildSBOM(goModPath string) (sbom, error) {
	goModuleComponents, err := goModuleSBOMComponents(goModPath)
	if err != nil {
		return sbom{}, err
	}
	components := []component{
		{BOMRef: "pkg:local/services-controlplane", Name: "services/controlplane", Type: "application", License: "FIRST-PARTY"},
		{BOMRef: "pkg:local/agent", Name: "agent", Type: "application", License: "FIRST-PARTY"},
		{BOMRef: "pkg:local/packages-rulecompiler", Name: "packages/rulecompiler", Type: "library", License: "FIRST-PARTY"},
		{BOMRef: "pkg:local/apps-web", Name: "apps/web", Type: "web-assets", License: "FIRST-PARTY"},
	}
	components = append(components, goModuleComponents...)

	dependsOn := make([]string, 0, len(components))
	for _, item := range components {
		if item.BOMRef != "" {
			dependsOn = append(dependsOn, item.BOMRef)
		}
	}
	sort.Strings(dependsOn)

	doc := sbom{
		Name:       "sing-box-next-panel",
		Type:       "cyclonedx-lite",
		Generated:  time.Now().UTC(),
		GoVersion:  runtime.Version(),
		Components: components,
		Dependencies: []dependency{
			{Ref: "pkg:local/sing-box-next-panel", DependsOn: dependsOn},
		},
	}
	return doc, nil
}

func goModuleSBOMComponents(path string) ([]component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	requirements := parseGoModRequirements(string(data))
	sort.Slice(requirements, func(i, j int) bool {
		return requirements[i].Path < requirements[j].Path
	})

	components := make([]component, 0, len(requirements))
	for _, requirement := range requirements {
		licenseID := reviewedDependencyLicenses[requirement.Path]
		if licenseID == "" {
			licenseID = "UNKNOWN"
		}
		components = append(components, component{
			BOMRef:  "pkg:golang/" + requirement.Path + "@" + requirement.Version,
			Name:    requirement.Path,
			Type:    "go-module",
			Version: requirement.Version,
			License: licenseID,
		})
	}
	return components, nil
}

func parseGoModRequirements(text string) []moduleRequirement {
	var requirements []moduleRequirement
	seen := map[string]struct{}{}
	inRequireBlock := false

	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(stripGoModComment(scanner.Text()))
		if line == "" {
			continue
		}
		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			addRequirement(line, seen, &requirements)
			continue
		}
		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if strings.HasPrefix(line, "require ") {
			requireLine := strings.TrimSpace(strings.TrimPrefix(line, "require "))
			if requireLine == "(" {
				inRequireBlock = true
				continue
			}
			addRequirement(requireLine, seen, &requirements)
		}
	}
	return requirements
}

func addRequirement(line string, seen map[string]struct{}, requirements *[]moduleRequirement) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	path := fields[0]
	version := fields[1]
	if _, ok := seen[path]; ok {
		return
	}
	seen[path] = struct{}{}
	*requirements = append(*requirements, moduleRequirement{Path: path, Version: version})
}

func stripGoModComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		return line[:idx]
	}
	return line
}

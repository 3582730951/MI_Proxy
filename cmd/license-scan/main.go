package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type moduleRequirement struct {
	Path    string
	Version string
}

type licenseComponent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Kind    string `json:"kind"`
	License string `json:"license"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
}

type licenseFinding struct {
	Component string `json:"component"`
	License   string `json:"license"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
}

type licensePolicy struct {
	AllowedLicenses         []string `json:"allowedLicenses"`
	ForbiddenLicenses       []string `json:"forbiddenLicenses"`
	UnknownDependencyAction string   `json:"unknownDependencyAction"`
}

type licenseReport struct {
	GeneratedAt time.Time          `json:"generatedAt"`
	Policy      licensePolicy      `json:"policy"`
	Passed      bool               `json:"passed"`
	Components  []licenseComponent `json:"components"`
	Findings    []licenseFinding   `json:"findings"`
}

var knownDependencyLicenses = map[string]string{
	"github.com/andybalholm/brotli": "MIT",
}

var firstPartyComponents = []licenseComponent{
	{Name: "services/controlplane", Kind: "application", License: "FIRST-PARTY", Status: "allowed", Reason: "first-party project component"},
	{Name: "agent", Kind: "application", License: "FIRST-PARTY", Status: "allowed", Reason: "first-party project component"},
	{Name: "packages/rulecompiler", Kind: "library", License: "FIRST-PARTY", Status: "allowed", Reason: "first-party project component"},
	{Name: "apps/web", Kind: "web-assets", License: "FIRST-PARTY", Status: "allowed", Reason: "first-party project component"},
}

var allowedLicenseIDs = map[string]struct{}{
	"APACHE-2.0":   {},
	"BSD-2-CLAUSE": {},
	"BSD-3-CLAUSE": {},
	"FIRST-PARTY":  {},
	"ISC":          {},
	"MIT":          {},
	"MPL-2.0":      {},
}

var forbiddenLicenseIDs = map[string]struct{}{
	"AGPL-3.0":          {},
	"AGPL-3.0-ONLY":     {},
	"AGPL-3.0-OR-LATER": {},
	"BUSL-1.1":          {},
	"COMMONS-CLAUSE":    {},
	"GPL-3.0":           {},
	"GPL-3.0-ONLY":      {},
	"GPL-3.0-OR-LATER":  {},
	"SSPL-1.0":          {},
}

func main() {
	goModPath := "go.mod"
	if len(os.Args) > 1 {
		goModPath = os.Args[1]
	}

	report, err := scanGoMod(goModPath, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "license scan failed: %v\n", err)
		os.Exit(2)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "license scan failed: %v\n", err)
		os.Exit(2)
	}
	if !report.Passed {
		os.Exit(1)
	}
}

func scanGoMod(path string, generatedAt time.Time) (licenseReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return licenseReport{}, err
	}
	requirements := parseGoModRequirements(string(data))
	return evaluateRequirements(requirements, knownDependencyLicenses, generatedAt), nil
}

func evaluateRequirements(requirements []moduleRequirement, knownLicenses map[string]string, generatedAt time.Time) licenseReport {
	report := licenseReport{
		GeneratedAt: generatedAt,
		Policy: licensePolicy{
			AllowedLicenses:         sortedKeys(allowedLicenseIDs),
			ForbiddenLicenses:       sortedKeys(forbiddenLicenseIDs),
			UnknownDependencyAction: "block",
		},
		Passed:     true,
		Components: append([]licenseComponent{}, firstPartyComponents...),
		Findings:   []licenseFinding{},
	}

	sort.Slice(requirements, func(i, j int) bool {
		return requirements[i].Path < requirements[j].Path
	})

	for _, requirement := range requirements {
		licenseID, ok := knownLicenses[requirement.Path]
		component := licenseComponent{
			Name:    requirement.Path,
			Version: requirement.Version,
			Kind:    "go-module",
			License: licenseID,
			Status:  "allowed",
			Reason:  "known reviewed dependency license",
		}
		if !ok {
			component.License = "UNKNOWN"
			component.Status = "blocked"
			component.Reason = "dependency license is not registered"
			report.Findings = append(report.Findings, licenseFinding{
				Component: requirement.Path,
				License:   "UNKNOWN",
				Severity:  "blocking",
				Message:   "external dependency must have an explicitly reviewed license before release",
			})
		} else if forbidden := firstForbiddenLicense(licenseID); forbidden != "" {
			component.Status = "blocked"
			component.Reason = "dependency uses a forbidden license"
			report.Findings = append(report.Findings, licenseFinding{
				Component: requirement.Path,
				License:   licenseID,
				Severity:  "blocking",
				Message:   "dependency license contains forbidden license identifier " + forbidden,
			})
		} else if !licenseExpressionAllowed(licenseID) {
			component.Status = "blocked"
			component.Reason = "dependency license is not in the allowlist"
			report.Findings = append(report.Findings, licenseFinding{
				Component: requirement.Path,
				License:   licenseID,
				Severity:  "blocking",
				Message:   "dependency license must be added to the allowlist after review",
			})
		}
		report.Components = append(report.Components, component)
	}

	report.Passed = len(report.Findings) == 0
	return report
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

func firstForbiddenLicense(expression string) string {
	for _, term := range licenseTerms(expression) {
		if _, ok := forbiddenLicenseIDs[term]; ok {
			return term
		}
	}
	return ""
}

func licenseExpressionAllowed(expression string) bool {
	terms := licenseTerms(expression)
	if len(terms) == 0 {
		return false
	}
	for _, term := range terms {
		if _, ok := allowedLicenseIDs[term]; !ok {
			return false
		}
	}
	return true
}

func licenseTerms(expression string) []string {
	cleaned := strings.NewReplacer("(", " ", ")", " ", ",", " ", "+", " ", "|", " ").Replace(expression)
	rawTerms := strings.Fields(cleaned)
	var terms []string
	for _, raw := range rawTerms {
		term := strings.ToUpper(strings.TrimSpace(raw))
		switch term {
		case "", "AND", "OR", "WITH":
			continue
		default:
			terms = append(terms, term)
		}
	}
	return terms
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

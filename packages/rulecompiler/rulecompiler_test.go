package rulecompiler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDomainClassificationRegressionFiles(t *testing.T) {
	policy := compileDefaultPolicy(t)
	root := findRepoRoot(t)
	dir := filepath.Join(root, "tests", "rules", "domain-classification")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read regression directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			file, err := os.Open(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatalf("open cases: %v", err)
			}
			defer file.Close()

			cases, err := ParseTestCases(file)
			if err != nil {
				t.Fatalf("parse cases: %v", err)
			}
			passed, failed := Evaluate(policy, cases)
			if len(failed) > 0 {
				t.Fatalf("passed %d/%d, failures: %v", passed, len(cases), failed)
			}
		})
	}
}

func TestCompileHundredThousandRulesUnderFiveSeconds(t *testing.T) {
	rules := make([]Rule, 100_000)
	for i := range rules {
		rules[i] = Rule{
			ID:       fmt.Sprintf("direct-%06d", i),
			Priority: 1000 + i,
			Type:     RuleDomainSuffix,
			Matcher:  fmt.Sprintf("site-%06d.cn", i),
			Outbound: OutboundDirect,
			Source:   "perf-test",
			Enabled:  true,
		}
	}
	start := time.Now()
	policy, err := Compile(CompileOptions{Rules: rules})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("100k rule compile took %s, want <5s", elapsed)
	}
	got := policy.Classify("www.site-099999.cn")
	if got.Outbound != OutboundDirect {
		t.Fatalf("classified %s, want direct", got.Outbound)
	}
}

func TestCoverageSamplesForLargeRuleSetsAreBoundedAndRepresentative(t *testing.T) {
	rules := make([]Rule, 2_000)
	for i := range rules {
		rules[i] = Rule{
			ID:       fmt.Sprintf("bulk-%04d", i),
			Priority: 1000 + i,
			Type:     RuleDomainSuffix,
			Matcher:  fmt.Sprintf("bulk-%04d.example", i),
			Outbound: OutboundDirect,
			Source:   "bulk-sample-test",
			Enabled:  true,
		}
	}

	samples := CoverageSamplesForRules(rules)
	if len(samples) > maxRuleImpactSamples+6 {
		t.Fatalf("large coverage sample set too large: %d", len(samples))
	}
	if !hasSample(samples, "bulk-0000.example") || !hasSample(samples, "bulk-1999.example") {
		t.Fatalf("bounded samples must keep head and tail rule evidence: %v", samples)
	}
}

func TestMillionDomainClassificationAccuracy(t *testing.T) {
	policy := compileDefaultPolicy(t)
	for i := 0; i < 1_000_000; i++ {
		var input string
		var want Outbound
		switch i % 5 {
		case 0:
			input, want = fmt.Sprintf("shop-%d.taobao.com", i), OutboundDirect
		case 1:
			input, want = fmt.Sprintf("gov-%d.gov.cn", i), OutboundDirect
		case 2:
			input, want = "scholar.google.com", OutboundProxy
		case 3:
			input, want = fmt.Sprintf("video-%d.example-warp-target.com", i), OutboundWarp
		default:
			input, want = fmt.Sprintf("global-%d.example.net", i), OutboundProxy
		}
		got := policy.Classify(input)
		if got.Outbound != want {
			t.Fatalf("case %d: %s expected %s got %s", i, input, want, got.Outbound)
		}
	}
}

func TestConflictDetectionBlocksPublish(t *testing.T) {
	_, err := Compile(CompileOptions{
		Rules: []Rule{
			{ID: "a", Priority: 10, Type: RuleDomainSuffix, Matcher: "example.com", Outbound: OutboundDirect, Enabled: true},
			{ID: "b", Priority: 11, Type: RuleDomainSuffix, Matcher: "example.com", Outbound: OutboundWarp, Enabled: true},
		},
	})
	if err == nil || !IsConflictError(err) {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestGoogleScholarCannotBeAddedToWarp(t *testing.T) {
	_, err := Compile(CompileOptions{WarpInclude: []string{"scholar.google.com"}})
	if err == nil || !IsConflictError(err) {
		t.Fatalf("expected Google Scholar WARP conflict, got %v", err)
	}
}

func TestBroadGoogleWarpRuleDoesNotOverrideScholarExclude(t *testing.T) {
	policy, err := Compile(CompileOptions{WarpInclude: []string{"google.com"}})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	got := policy.Classify("scholar.google.com")
	if got.Outbound != OutboundProxy {
		t.Fatalf("scholar.google.com routed to %s, want proxy-default", got.Outbound)
	}
}

func TestAdvancedRuleDimensionsAndCoverageAnalysis(t *testing.T) {
	policy, err := Compile(CompileOptions{
		Rules: []Rule{
			{ID: "geoip-test", Priority: 100, Type: RuleGeoIP, Matcher: "198.51.100.0/24", Outbound: OutboundBlock, Source: "test", Enabled: true},
			{ID: "ruleset-test", Priority: 101, Type: RuleRuleSet, Matcher: "cn-bank", Outbound: OutboundDirect, Source: "test", Enabled: true},
			{ID: "process-test", Priority: 102, Type: RuleProcessName, Matcher: "curl", Outbound: OutboundProxy, Source: "test", Enabled: true},
			{ID: "port-test", Priority: 103, Type: RulePort, Matcher: "443", Outbound: OutboundWarp, Source: "test", Enabled: true},
			{ID: "protocol-test", Priority: 104, Type: RuleProtocol, Matcher: "tuic", Outbound: OutboundWarp, Source: "test", Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("compile advanced dimensions: %v", err)
	}
	for _, tc := range []struct {
		input string
		want  Outbound
	}{
		{"198.51.100.42", OutboundBlock},
		{"cn-bank", OutboundDirect},
		{"curl", OutboundProxy},
		{"443", OutboundWarp},
		{"tuic", OutboundWarp},
	} {
		if got := policy.Classify(tc.input); got.Outbound != tc.want {
			t.Fatalf("classify %q got %s want %s via %+v", tc.input, got.Outbound, tc.want, got)
		}
	}
	coverage := AnalyzeCoverage(policy, CoverageSamplesForRules(policy.Rules()))
	if coverage.TotalSamples == 0 || coverage.ByOutbound[OutboundBlock] == 0 || coverage.ByOutbound[OutboundWarp] == 0 {
		t.Fatalf("coverage did not count advanced dimensions: %+v", coverage)
	}
	if !coverageHasRule(coverage, "geoip-test") || !coverageHasRule(coverage, "protocol-test") {
		t.Fatalf("coverage missing rule hit estimates: %+v", coverage.RuleHits)
	}
}

func TestDiffReportIncludesAddedRemovedChangedAndConflicts(t *testing.T) {
	oldRules := []Rule{
		{ID: "a", Priority: 1, Type: RuleDomainSuffix, Matcher: "keep.cn", Outbound: OutboundDirect, Enabled: true},
		{ID: "b", Priority: 2, Type: RuleDomainSuffix, Matcher: "remove.cn", Outbound: OutboundDirect, Enabled: true},
		{ID: "c", Priority: 3, Type: RuleDomainSuffix, Matcher: "change.net", Outbound: OutboundProxy, Enabled: true},
	}
	newRules := []Rule{
		{ID: "a", Priority: 1, Type: RuleDomainSuffix, Matcher: "keep.cn", Outbound: OutboundDirect, Enabled: true},
		{ID: "d", Priority: 2, Type: RuleDomainSuffix, Matcher: "add.cn", Outbound: OutboundDirect, Enabled: true},
		{ID: "c", Priority: 3, Type: RuleDomainSuffix, Matcher: "change.net", Outbound: OutboundWarp, Enabled: true},
		{ID: "e", Priority: 4, Type: RuleDomainSuffix, Matcher: "dupe.net", Outbound: OutboundDirect, Enabled: true},
		{ID: "f", Priority: 5, Type: RuleDomainSuffix, Matcher: "dupe.net", Outbound: OutboundProxy, Enabled: true},
	}
	report := Diff(oldRules, newRules)
	if len(report.Added) != 2 || len(report.Removed) != 1 || len(report.Changed) != 1 || len(report.Conflicts) != 1 {
		t.Fatalf("unexpected diff report: %+v", report)
	}
	if !hasHitChange(report.HitChanges, "change.net", OutboundProxy, OutboundWarp) {
		t.Fatalf("diff report missing changed hit impact: %+v", report.HitChanges)
	}
	if !hasHitChange(report.HitChanges, "remove.cn", OutboundDirect, OutboundProxy) {
		t.Fatalf("diff report missing removed hit impact: %+v", report.HitChanges)
	}
}

func hasHitChange(changes []HitChange, input string, previous, next Outbound) bool {
	for _, change := range changes {
		if change.Input == input && change.PreviousOutbound == previous && change.NextOutbound == next {
			return true
		}
	}
	return false
}

func hasSample(samples []string, want string) bool {
	for _, sample := range samples {
		if sample == want {
			return true
		}
	}
	return false
}

func coverageHasRule(report CoverageReport, ruleID string) bool {
	for _, hit := range report.RuleHits {
		if hit.RuleID == ruleID && hit.Hits > 0 && hit.HitRate > 0 {
			return true
		}
	}
	return false
}

func compileDefaultPolicy(t *testing.T) *CompiledPolicy {
	t.Helper()
	policy, err := Compile(CompileOptions{
		WarpInclude: []string{
			"example-warp-target.com",
			"warp-only.example",
		},
		UserDirect: []string{
			"custom-direct.example.cn",
		},
	})
	if err != nil {
		t.Fatalf("compile default policy: %v", err)
	}
	return policy
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

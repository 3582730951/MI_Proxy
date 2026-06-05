package rulecompiler

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Outbound string

const (
	OutboundDirect Outbound = "direct"
	OutboundProxy  Outbound = "proxy-default"
	OutboundWarp   Outbound = "warp-pool"
	OutboundBlock  Outbound = "block"
)

type RuleType string

const (
	RuleDomain        RuleType = "domain"
	RuleDomainSuffix  RuleType = "domain_suffix"
	RuleDomainKeyword RuleType = "domain_keyword"
	RuleDomainRegex   RuleType = "domain_regex"
	RuleGeoIP         RuleType = "geoip"
	RuleRuleSet       RuleType = "rule_set"
	RuleIPCidr        RuleType = "ip_cidr"
	RuleProcessName   RuleType = "process_name"
	RulePort          RuleType = "port"
	RuleProtocol      RuleType = "protocol"
)

type Rule struct {
	ID       string
	Priority int
	Type     RuleType
	Matcher  string
	Outbound Outbound
	Source   string
	Enabled  bool
}

type CompileOptions struct {
	DefaultOutbound Outbound
	Rules           []Rule
	WarpInclude     []string
	WarpExclude     []string
	UserDirect      []string
	RolloutPercent  int
	Now             time.Time
}

type Classification struct {
	Input          string
	Outbound       Outbound
	Reason         string
	RuleID         string
	MatchedRule    string
	MatchedSource  string
	MatchedRuleTyp RuleType
}

type CompiledPolicy struct {
	defaultOutbound Outbound
	rules           []compiledRule
	conflicts       []Conflict
	compiledAt      time.Time
}

type Conflict struct {
	RuleA  string
	RuleB  string
	Reason string
}

type HitChange struct {
	Input            string
	PreviousOutbound Outbound
	NextOutbound     Outbound
	PreviousRuleID   string
	NextRuleID       string
	PreviousReason   string
	NextReason       string
}

type DiffReport struct {
	Added          []Rule
	Removed        []Rule
	Changed        []Rule
	Conflicts      []Conflict
	HitChanges     []HitChange
	Coverage       CoverageReport
	RolloutPercent int
}

type CoverageReport struct {
	TotalSamples int
	ByOutbound   map[Outbound]int
	FallbackHits int
	RuleHits     []RuleHitEstimate
}

type RuleHitEstimate struct {
	RuleID   string
	Matcher  string
	Source   string
	Outbound Outbound
	Hits     int
	HitRate  float64
}

type TestCase struct {
	Input            string
	ExpectedOutbound Outbound
	Reason           string
}

type compiledRule struct {
	rule   Rule
	regex  *regexp.Regexp
	prefix netip.Prefix
}

const maxRuleImpactSamples = 128

var scholarExcludes = []string{
	"scholar.google.com",
	"scholar.googleusercontent.com",
	"citations.google.com",
	"academic.google.com",
	"google.com/scholar",
}

var cnDomainSuffixes = []string{
	"10010.com",
	"10086.cn",
	"12306.cn",
	"alipay.com",
	"amap.com",
	"baidu.com",
	"bilibili.com",
	"chinaunicom.cn",
	"chinabank.com.cn",
	"chinacache.com",
	"chinamobile.com",
	"ctyun.cn",
	"edu.cn",
	"gov.cn",
	"icbc.com.cn",
	"jd.com",
	"mi.com",
	"qq.com",
	"taobao.com",
	"tencent.com",
	"tmall.com",
	"weibo.com",
	"xiaomi.com",
}

var cnCIDRStrings = []string{
	"1.0.1.0/24",
	"14.0.0.0/8",
	"27.0.0.0/8",
	"36.0.0.0/8",
	"39.0.0.0/8",
	"42.0.0.0/8",
	"49.0.0.0/8",
	"58.0.0.0/7",
	"101.0.0.0/8",
	"103.0.0.0/8",
	"106.0.0.0/8",
	"110.0.0.0/8",
	"111.0.0.0/8",
	"112.0.0.0/5",
	"120.0.0.0/6",
	"139.0.0.0/8",
	"140.0.0.0/8",
	"150.0.0.0/8",
	"171.0.0.0/8",
	"175.0.0.0/8",
	"180.0.0.0/6",
	"202.0.0.0/7",
	"211.0.0.0/8",
	"218.0.0.0/7",
	"240e::/20",
}

var privateCIDRStrings = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

var cnCIDRs = parsePrefixes(cnCIDRStrings)
var privateCIDRs = parsePrefixes(privateCIDRStrings)

func Compile(opts CompileOptions) (*CompiledPolicy, error) {
	if opts.DefaultOutbound == "" {
		opts.DefaultOutbound = OutboundProxy
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}

	var all []Rule
	priority := 0
	addSystem := func(kind RuleType, matcher string, outbound Outbound, source string) {
		priority++
		all = append(all, Rule{
			ID:       fmt.Sprintf("%s:%s", source, matcher),
			Priority: priority,
			Type:     kind,
			Matcher:  matcher,
			Outbound: outbound,
			Source:   source,
			Enabled:  true,
		})
	}

	for _, cidr := range privateCIDRStrings {
		addSystem(RuleIPCidr, cidr, OutboundDirect, "builtin-private")
	}
	for _, suffix := range cnDomainSuffixes {
		addSystem(RuleDomainSuffix, suffix, OutboundDirect, "builtin-geosite-cn")
	}
	for _, cidr := range cnCIDRStrings {
		addSystem(RuleIPCidr, cidr, OutboundDirect, "builtin-geoip-cn")
	}
	for _, matcher := range opts.UserDirect {
		addSystem(bestDomainRuleType(matcher), matcher, OutboundDirect, "user-direct")
	}
	for _, matcher := range scholarExcludes {
		addSystem(bestDomainRuleType(matcher), matcher, OutboundProxy, "warp-exclude-google-scholar")
	}
	for _, matcher := range opts.WarpExclude {
		addSystem(bestDomainRuleType(matcher), matcher, OutboundProxy, "user-warp-exclude")
	}
	for _, matcher := range opts.WarpInclude {
		addSystem(bestDomainRuleType(matcher), matcher, OutboundWarp, "user-warp-include")
	}
	for _, rule := range opts.Rules {
		if rule.Enabled {
			if rule.ID == "" {
				rule.ID = fmt.Sprintf("user:%s:%s", rule.Type, rule.Matcher)
			}
			all = append(all, normalizeRule(rule))
		}
	}

	conflicts := detectConflicts(all)
	if len(conflicts) > 0 {
		return nil, fmt.Errorf("rule conflicts detected: %w", ConflictError{Conflicts: conflicts})
	}

	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Priority == all[j].Priority {
			return all[i].ID < all[j].ID
		}
		return all[i].Priority < all[j].Priority
	})

	compiled := make([]compiledRule, 0, len(all))
	for _, rule := range all {
		cr := compiledRule{rule: rule}
		switch rule.Type {
		case RuleDomainRegex:
			re, err := regexp.Compile(rule.Matcher)
			if err != nil {
				return nil, fmt.Errorf("invalid domain regex %q: %w", rule.Matcher, err)
			}
			cr.regex = re
		case RuleIPCidr, RuleGeoIP:
			prefix, err := netip.ParsePrefix(rule.Matcher)
			if err != nil {
				return nil, fmt.Errorf("invalid ip cidr %q: %w", rule.Matcher, err)
			}
			cr.prefix = prefix
		}
		compiled = append(compiled, cr)
	}

	return &CompiledPolicy{
		defaultOutbound: opts.DefaultOutbound,
		rules:           compiled,
		compiledAt:      opts.Now,
	}, nil
}

func (p *CompiledPolicy) Classify(input string) Classification {
	normalized := normalizeInput(input)
	for _, cr := range p.rules {
		if cr.matches(normalized) {
			return Classification{
				Input:          input,
				Outbound:       cr.rule.Outbound,
				Reason:         cr.rule.Source,
				RuleID:         cr.rule.ID,
				MatchedRule:    cr.rule.Matcher,
				MatchedSource:  cr.rule.Source,
				MatchedRuleTyp: cr.rule.Type,
			}
		}
	}
	return Classification{
		Input:    input,
		Outbound: p.defaultOutbound,
		Reason:   "final",
	}
}

func (p *CompiledPolicy) ClassifyMany(inputs []string) []Classification {
	results := make([]Classification, len(inputs))
	for i, input := range inputs {
		results[i] = p.Classify(input)
	}
	return results
}

func (p *CompiledPolicy) Rules() []Rule {
	rules := make([]Rule, 0, len(p.rules))
	for _, rule := range p.rules {
		rules = append(rules, rule.rule)
	}
	return rules
}

func CoverageSamplesForRules(rules []Rule) []string {
	inputs := []string{
		"10.0.0.1",
		"101.6.6.6",
		"www.taobao.com",
		"scholar.google.com",
		"example-warp-target.com",
		"global.example.net",
	}
	for _, rule := range limitRulesForSamples(rules, maxRuleImpactSamples) {
		if sample := sampleInputForRule(rule); sample != "" {
			inputs = append(inputs, sample)
		}
	}
	seen := map[string]struct{}{}
	deduped := make([]string, 0, len(inputs))
	for _, input := range inputs {
		input = normalizeInput(input)
		if input == "" {
			continue
		}
		if _, ok := seen[input]; ok {
			continue
		}
		seen[input] = struct{}{}
		deduped = append(deduped, input)
	}
	sort.Strings(deduped)
	return deduped
}

func AnalyzeCoverage(policy *CompiledPolicy, samples []string) CoverageReport {
	report := CoverageReport{ByOutbound: map[Outbound]int{}}
	if policy == nil {
		return report
	}
	hits := map[string]RuleHitEstimate{}
	for _, sample := range samples {
		if strings.TrimSpace(sample) == "" {
			continue
		}
		report.TotalSamples++
		classification := policy.Classify(sample)
		report.ByOutbound[classification.Outbound]++
		if classification.RuleID == "" {
			report.FallbackHits++
			continue
		}
		estimate := hits[classification.RuleID]
		estimate.RuleID = classification.RuleID
		estimate.Matcher = classification.MatchedRule
		estimate.Source = classification.MatchedSource
		estimate.Outbound = classification.Outbound
		estimate.Hits++
		hits[classification.RuleID] = estimate
	}
	report.RuleHits = make([]RuleHitEstimate, 0, len(hits))
	for _, estimate := range hits {
		if report.TotalSamples > 0 {
			estimate.HitRate = float64(estimate.Hits) / float64(report.TotalSamples)
		}
		report.RuleHits = append(report.RuleHits, estimate)
	}
	sort.SliceStable(report.RuleHits, func(i, j int) bool {
		if report.RuleHits[i].Hits == report.RuleHits[j].Hits {
			return report.RuleHits[i].RuleID < report.RuleHits[j].RuleID
		}
		return report.RuleHits[i].Hits > report.RuleHits[j].Hits
	})
	return report
}

func Diff(oldRules, newRules []Rule) DiffReport {
	oldMap := map[string]Rule{}
	newMap := map[string]Rule{}
	for _, rule := range oldRules {
		oldMap[ruleKey(rule)] = normalizeRule(rule)
	}
	for _, rule := range newRules {
		newMap[ruleKey(rule)] = normalizeRule(rule)
	}

	report := DiffReport{}
	for key, next := range newMap {
		prev, ok := oldMap[key]
		if !ok {
			report.Added = append(report.Added, next)
			continue
		}
		if prev.Outbound != next.Outbound || prev.Priority != next.Priority || prev.Enabled != next.Enabled || prev.Source != next.Source {
			report.Changed = append(report.Changed, next)
		}
	}
	for key, prev := range oldMap {
		if _, ok := newMap[key]; !ok {
			report.Removed = append(report.Removed, prev)
		}
	}
	report.Conflicts = detectConflicts(newRules)
	report.HitChanges = diffHitChanges(oldRules, newRules, report)
	sortRules(report.Added)
	sortRules(report.Removed)
	sortRules(report.Changed)
	sortHitChanges(report.HitChanges)
	return report
}

func diffHitChanges(oldRules, newRules []Rule, report DiffReport) []HitChange {
	candidates := diffSampleInputs(report)
	if len(candidates) == 0 {
		return nil
	}
	oldPolicy := compileRulesForDiff(oldRules)
	newPolicy := compileRulesForDiff(newRules)
	seen := map[string]struct{}{}
	var changes []HitChange
	for _, input := range candidates {
		input = normalizeInput(input)
		if input == "" {
			continue
		}
		if _, ok := seen[input]; ok {
			continue
		}
		seen[input] = struct{}{}
		prev := oldPolicy.Classify(input)
		next := newPolicy.Classify(input)
		if prev.Outbound == next.Outbound && prev.RuleID == next.RuleID && prev.Reason == next.Reason {
			continue
		}
		changes = append(changes, HitChange{
			Input:            input,
			PreviousOutbound: prev.Outbound,
			NextOutbound:     next.Outbound,
			PreviousRuleID:   prev.RuleID,
			NextRuleID:       next.RuleID,
			PreviousReason:   prev.Reason,
			NextReason:       next.Reason,
		})
	}
	return changes
}

func diffSampleInputs(report DiffReport) []string {
	var inputs []string
	addRule := func(rule Rule) {
		if sample := sampleInputForRule(rule); sample != "" {
			inputs = append(inputs, sample)
		}
	}
	for _, rule := range report.Added {
		addRule(rule)
	}
	for _, rule := range report.Removed {
		addRule(rule)
	}
	for _, rule := range report.Changed {
		addRule(rule)
	}
	conflictRules := map[string]struct{}{}
	for _, conflict := range report.Conflicts {
		conflictRules[conflict.RuleA] = struct{}{}
		conflictRules[conflict.RuleB] = struct{}{}
	}
	if len(conflictRules) > 0 {
		for _, rule := range append(report.Added, report.Changed...) {
			if _, ok := conflictRules[rule.ID]; ok {
				addRule(rule)
			}
		}
	}
	return limitStringSamples(inputs, maxRuleImpactSamples)
}

func limitRulesForSamples(rules []Rule, limit int) []Rule {
	if limit <= 0 || len(rules) <= limit {
		return rules
	}
	front := limit / 2
	back := limit - front
	limited := make([]Rule, 0, limit)
	limited = append(limited, rules[:front]...)
	limited = append(limited, rules[len(rules)-back:]...)
	return limited
}

func limitStringSamples(inputs []string, limit int) []string {
	if limit <= 0 || len(inputs) <= limit {
		return inputs
	}
	front := limit / 2
	back := limit - front
	limited := make([]string, 0, limit)
	limited = append(limited, inputs[:front]...)
	limited = append(limited, inputs[len(inputs)-back:]...)
	return limited
}

func sampleInputForRule(rule Rule) string {
	rule = normalizeRule(rule)
	switch rule.Type {
	case RuleDomain, RuleDomainSuffix, RuleDomainKeyword, RuleRuleSet, RuleProcessName, RulePort, RuleProtocol:
		return strings.TrimPrefix(rule.Matcher, ".")
	case RuleIPCidr, RuleGeoIP:
		prefix, err := netip.ParsePrefix(rule.Matcher)
		if err != nil {
			return ""
		}
		return prefix.Addr().String()
	case RuleDomainRegex:
		return ""
	default:
		return rule.Matcher
	}
}

func compileRulesForDiff(rules []Rule) *CompiledPolicy {
	normalized := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		normalized = append(normalized, normalizeRule(rule))
	}
	sortRules(normalized)
	compiled := make([]compiledRule, 0, len(normalized))
	for _, rule := range normalized {
		cr := compiledRule{rule: rule}
		switch rule.Type {
		case RuleDomainRegex:
			re, err := regexp.Compile(rule.Matcher)
			if err != nil {
				continue
			}
			cr.regex = re
		case RuleIPCidr, RuleGeoIP:
			prefix, err := netip.ParsePrefix(rule.Matcher)
			if err != nil {
				continue
			}
			cr.prefix = prefix
		}
		compiled = append(compiled, cr)
	}
	return &CompiledPolicy{defaultOutbound: OutboundProxy, rules: compiled}
}

func ParseTestCases(reader io.Reader) ([]TestCase, error) {
	records, err := csv.NewReader(reader).ReadAll()
	if err != nil {
		return nil, err
	}
	cases := make([]TestCase, 0, len(records))
	for line, record := range records {
		if len(record) == 0 || strings.HasPrefix(strings.TrimSpace(record[0]), "#") {
			continue
		}
		if len(record) != 3 {
			return nil, fmt.Errorf("line %d: want 3 columns, got %d", line+1, len(record))
		}
		cases = append(cases, TestCase{
			Input:            strings.TrimSpace(record[0]),
			ExpectedOutbound: Outbound(strings.TrimSpace(record[1])),
			Reason:           strings.TrimSpace(record[2]),
		})
	}
	return cases, nil
}

func Evaluate(policy *CompiledPolicy, cases []TestCase) (passed int, failed []string) {
	for _, tc := range cases {
		got := policy.Classify(tc.Input)
		if got.Outbound == tc.ExpectedOutbound {
			passed++
			continue
		}
		failed = append(failed, fmt.Sprintf("%s expected %s got %s (%s)", tc.Input, tc.ExpectedOutbound, got.Outbound, got.Reason))
	}
	return passed, failed
}

type ConflictError struct {
	Conflicts []Conflict
}

func (e ConflictError) Error() string {
	return fmt.Sprintf("%d conflicts", len(e.Conflicts))
}

func IsConflictError(err error) bool {
	var conflict ConflictError
	return errors.As(err, &conflict)
}

func (cr compiledRule) matches(input string) bool {
	switch cr.rule.Type {
	case RuleDomain:
		return input == normalizeInput(cr.rule.Matcher)
	case RuleDomainSuffix:
		return matchDomainSuffix(input, cr.rule.Matcher)
	case RuleDomainKeyword:
		return strings.Contains(input, strings.ToLower(cr.rule.Matcher))
	case RuleDomainRegex:
		return cr.regex.MatchString(input)
	case RuleGeoIP, RuleIPCidr:
		addr, err := netip.ParseAddr(input)
		return err == nil && cr.prefix.Contains(addr)
	case RuleRuleSet:
		return input == strings.ToLower(cr.rule.Matcher)
	case RuleProcessName, RulePort, RuleProtocol:
		return input == strings.ToLower(cr.rule.Matcher)
	default:
		return false
	}
}

func detectConflicts(rules []Rule) []Conflict {
	seen := map[string]Rule{}
	var conflicts []Conflict
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		norm := normalizeRule(rule)
		if norm.Outbound == OutboundWarp && isScholarMatcher(norm.Matcher) {
			conflicts = append(conflicts, Conflict{
				RuleA:  norm.ID,
				RuleB:  "warp-exclude-google-scholar",
				Reason: "Google Scholar must never route to WARP",
			})
		}
		key := ruleKey(norm)
		if prev, ok := seen[key]; ok && prev.Outbound != norm.Outbound {
			conflicts = append(conflicts, Conflict{
				RuleA:  prev.ID,
				RuleB:  norm.ID,
				Reason: fmt.Sprintf("%s/%s has different outbounds: %s vs %s", norm.Type, norm.Matcher, prev.Outbound, norm.Outbound),
			})
			continue
		}
		seen[key] = norm
	}
	return conflicts
}

func normalizeRule(rule Rule) Rule {
	rule.Matcher = strings.TrimSpace(strings.ToLower(rule.Matcher))
	if rule.Type == "" {
		rule.Type = bestDomainRuleType(rule.Matcher)
	}
	return rule
}

func normalizeInput(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimRight(input, ".")
	if slash := strings.Index(input, "/"); slash > 0 {
		path := input[slash:]
		host := input[:slash]
		if host == "google.com" && strings.HasPrefix(path, "/scholar") {
			return "google.com/scholar"
		}
		return host
	}
	return input
}

func bestDomainRuleType(matcher string) RuleType {
	matcher = strings.TrimSpace(strings.ToLower(matcher))
	if strings.Contains(matcher, "/") {
		return RuleDomain
	}
	if strings.HasPrefix(matcher, ".") {
		return RuleDomainSuffix
	}
	if _, err := netip.ParsePrefix(matcher); err == nil {
		return RuleIPCidr
	}
	if strings.ContainsAny(matcher, "*?[]()+|^$") {
		return RuleDomainRegex
	}
	return RuleDomainSuffix
}

func matchDomainSuffix(input, suffix string) bool {
	suffix = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(suffix)), ".")
	input = normalizeInput(input)
	return input == suffix || strings.HasSuffix(input, "."+suffix)
}

func isScholarMatcher(matcher string) bool {
	for _, exclude := range scholarExcludes {
		if matchDomainSuffix(matcher, exclude) || matcher == exclude {
			return true
		}
	}
	return matcher == "google.com/scholar"
}

func ruleKey(rule Rule) string {
	norm := normalizeRule(rule)
	return string(norm.Type) + "\x00" + norm.Matcher
}

func sortRules(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority < rules[j].Priority
	})
}

func sortHitChanges(changes []HitChange) {
	sort.SliceStable(changes, func(i, j int) bool {
		return changes[i].Input < changes[j].Input
	})
}

func parsePrefixes(prefixes []string) []netip.Prefix {
	parsed := make([]netip.Prefix, 0, len(prefixes))
	for _, cidr := range prefixes {
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil {
			parsed = append(parsed, prefix)
		}
	}
	return parsed
}

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardIncludesRequiredNavigationAndMetrics(t *testing.T) {
	html, err := os.ReadFile("index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	page := string(html)

	for _, label := range []string{
		"Overview",
		"Nodes",
		"Routes &amp; Rules",
		"Subscriptions",
		"WARP Pool",
		"Protocols",
		"Traffic",
		"Observability",
		"Security",
		"Deployments",
		"Incidents",
		"Settings",
	} {
		if !strings.Contains(page, label) {
			t.Fatalf("missing navigation label %q", label)
		}
	}

	for _, metric := range []string{
		"Online nodes",
		"Offline nodes",
		"Alerts",
		"Total connections",
		"Active connections",
		"New connection rate",
		"Total traffic",
		"Up / Down",
		"CPU / memory",
		"Disk / FD",
		"Ports",
		"Network PPS",
		"99p API latency",
		"Subscription latency",
		"Device",
		"Capacity tier",
		"Autoscaling recommendation",
		"Cost guardrail",
		"Region",
		"Protocol",
		"Outbound policy",
		"Config apply latency",
		"Google Scholar Exclusion",
		"SAST",
		"SCA",
		"DAST",
		"Secrets",
		"SBOM",
		"License risk",
		"CVE severity",
		"Waived gates",
		"Reason",
		"Passkey",
		"Route Decision Audit",
		"Recent Route Decisions",
		"Rule ID",
		"Matched source",
		"Recent flow",
		"Why",
		"hit change",
		"Coverage Analysis",
		"hit-rate estimate",
		"Rule Sources",
		"SSRF",
		"DNS",
		"WireGuard",
		"P0",
		"P1",
		"P2",
		"P3",
		"Switch exit",
		"Disable WARP profile",
		"Limit subscriptions",
		"Argo Tunnel",
	} {
		if !strings.Contains(page, metric) {
			t.Fatalf("missing metric %q", metric)
		}
	}
	if strings.Count(page, "<canvas") < 20 {
		t.Fatalf("dashboard has too few charts")
	}
}

func TestDashboardStaticAssetsArePresentAndLightweight(t *testing.T) {
	totalBytes := int64(0)
	for _, rel := range []string{"index.html", "styles.css", "app.js"} {
		info, err := os.Stat(filepath.Join(".", rel))
		if err != nil {
			t.Fatalf("missing dashboard asset %s: %v", rel, err)
		}
		totalBytes += info.Size()
	}
	if totalBytes > 200*1024 {
		t.Fatalf("dashboard first-screen assets are too large: %d bytes", totalBytes)
	}
}

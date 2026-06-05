package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardIncludesProductionNavigationAndMountPoints(t *testing.T) {
	html := readAsset(t, "index.html")

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
		if !strings.Contains(html, label) {
			t.Fatalf("missing navigation label %q", label)
		}
	}

	for _, id := range []string{
		"sessionForm",
		"metricGrid",
		"trafficMap",
		"nodeBody",
		"routeTraceBody",
		"subscriptionBody",
		"warpBody",
		"protocolGrid",
		"auditBody",
		"incidentBody",
	} {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Fatalf("missing production data mount point %s", id)
		}
	}
	if strings.Count(html, "<canvas") < 7 {
		t.Fatalf("dashboard has too few live chart canvases")
	}
	if !strings.Contains(readAsset(t, "app.js"), "function metricCard(") {
		t.Fatal("dashboard must render API-backed metric cards at runtime")
	}
}

func TestDashboardDoesNotShipDemoOperationalData(t *testing.T) {
	html := readAsset(t, "index.html")
	js := readAsset(t, "app.js")
	combined := html + "\n" + js

	for _, forbidden := range []string{
		"Online 36d 23h",
		"UTC+8 2025-05-28",
		"1.8M",
		"42.8 TB",
		"172.16.0.2",
		"ops@example",
		"hk-01",
		"sg-02",
		"v42",
		"example-warp-target.com",
		"www.taobao.com",
		"function classify(",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("dashboard still ships demo operational data %q", forbidden)
		}
	}
}

func TestDashboardUsesAuthenticatedAPIDataAndLiveMap(t *testing.T) {
	js := readAsset(t, "app.js")
	for _, required := range []string{
		"fetch(`${apiBase()}${path}`",
		"headers.Authorization",
		"sessionStorage",
		"/api/v1/metrics/overview",
		"/api/v1/nodes",
		"/api/v1/warp/profiles",
		"/api/v1/routes/trace",
		"/api/v1/rules/test-domain",
		"renderTrafficMap",
		"coordinatesForRegion",
		"state.data.nodes",
	} {
		if !strings.Contains(js, required) {
			t.Fatalf("dashboard missing live API/map behavior %s", required)
		}
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
	if totalBytes > 260*1024 {
		t.Fatalf("dashboard first-screen assets are too large: %d bytes", totalBytes)
	}
}

func readAsset(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

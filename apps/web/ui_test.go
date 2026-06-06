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
		"总览",
		"节点",
		"规则与路由",
		"订阅",
		"WARP 池",
		"协议",
		"流量",
		"可观测",
		"安全",
		"部署",
		"事件",
		"设置",
	} {
		if !strings.Contains(html, label) {
			t.Fatalf("missing navigation label %q", label)
		}
	}

	for _, id := range []string{
		"sessionForm",
		"usernameInput",
		"passwordInput",
		"metricGrid",
		"failurePill",
		"readinessStrip",
		"trafficMap",
		"runtimeInfo",
		"nodeBody",
		"routeTraceBody",
		"subscriptionForm",
		"copySubscriptionLinkButton",
		"recentSubscriptionLinks",
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
	if !strings.Contains(html, `lang="zh-CN"`) || !strings.Contains(html, "账号登录") {
		t.Fatal("dashboard must default to Chinese account/password login")
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
		"/api/v1/auth/login",
		"/api/v1/system/runtime",
		"headers.Authorization",
		"sessionStorage",
		"/api/v1/metrics/overview",
		"/api/v1/nodes",
		"/api/v1/warp/profiles",
		"/api/v1/routes/trace",
		"/api/v1/rules/test-domain",
		"/sub/",
		"handleCopySubscriptionLink",
		"renderRecentSubscriptionLinks",
		"data-subscription-copy-id",
		"renderReadiness",
		"safeErrorMessage",
		"navigator.clipboard",
		"renderTrafficMap",
		"coordinatesForRegion",
		"state.data.nodes",
	} {
		if !strings.Contains(js, required) {
			t.Fatalf("dashboard missing live API/map behavior %s", required)
		}
	}
	combined := readAsset(t, "index.html") + "\n" + js
	for _, forbidden := range []string{
		"authModeInput",
		"apiTokenInput",
		"Trusted gateway",
		"Bearer token",
		"Auth mode",
		"subscriptionResult.textContent = token",
		"subscriptionResult.textContent = state.lastSubscriptionLink",
		"textContent = state.lastSubscriptionLink",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("dashboard still exposes obsolete or sensitive auth UI %q", forbidden)
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

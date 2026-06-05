package controlplane

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"sing-box-next-panel/packages/rulecompiler"
)

func TestHTTPAdminAPIsRequireAuthentication(t *testing.T) {
	cp := New(nil)
	server := NewHTTPHandler(cp)
	health := httptest.NewRecorder()
	server.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || strings.Contains(health.Body.String(), "token") || strings.Contains(health.Body.String(), "secret") {
		t.Fatalf("health endpoint unsafe or unavailable: status=%d body=%s", health.Code, health.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/register", bytes.NewBufferString(`{"tenantID":"tenant-a"}`))
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated admin API status=%d, want 401", res.Code)
	}
}

func TestHTTPDashboardServedAtRoot(t *testing.T) {
	cp := New(nil)
	server := NewHTTPHandler(cp)

	root := httptest.NewRecorder()
	server.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/", nil))
	if root.Code != http.StatusOK {
		t.Fatalf("dashboard root status=%d body=%s", root.Code, root.Body.String())
	}
	if contentType := root.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("dashboard root content-type=%q, want text/html", contentType)
	}
	if body := root.Body.String(); !strings.Contains(body, "Sing-Box Pro") || !strings.Contains(body, "Overview") {
		t.Fatalf("dashboard root missing expected markup: %s", body)
	}
	csp := root.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "style-src 'self'") {
		t.Fatalf("dashboard CSP does not allow bundled static assets: %q", csp)
	}

	asset := httptest.NewRecorder()
	server.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if asset.Code != http.StatusOK || !strings.Contains(asset.Body.String(), "drawChart") {
		t.Fatalf("dashboard app asset unavailable: status=%d body=%s", asset.Code, asset.Body.String())
	}

	health := httptest.NewRecorder()
	server.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if csp := health.Header().Get("Content-Security-Policy"); strings.Contains(csp, "script-src") || strings.Contains(csp, "style-src") {
		t.Fatalf("health endpoint CSP should remain strict: %q", csp)
	}
}

func TestHTTPSubscriptionEndpointDoesNotExposeOtherTokens(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	_, token, err := cp.CreateSubscription(ctx, "tenant-a", "user-1", "sing-box", "policy-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	server := NewHTTPHandler(cp)
	req := httptest.NewRequest(http.MethodGet, "/sub/"+token+"/sing-box", nil)
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("subscription status=%d body=%s", res.Code, res.Body.String())
	}
	if bytes.Contains(res.Body.Bytes(), []byte(token)) {
		t.Fatal("subscription response leaked token")
	}
}

func TestHTTPAPIDraftEndpointsAreCovered(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	server := NewHTTPHandler(cp)
	headers := map[string]string{"X-User-ID": "admin", "X-Tenant-ID": "tenant-a", "X-Role": string(RoleAdmin), "X-Confirm-Token": ConfirmationToken("admin")}

	expectStatus(t, server, http.MethodPost, "/api/v1/nodes/register", `{"id":"node-1","tenantId":"tenant-a","name":"hk-01"}`, headers, http.StatusOK)
	expectStatus(t, server, http.MethodPost, "/api/v1/nodes/node-1/heartbeat", `{"kernelVersion":"6.8","congestionControl":"bbr","queueDiscipline":"fq","noFile":1048576,"somaxConn":4096,"tcpFastOpen":3,"portRangeStart":10000,"portRangeEnd":65000,"cpu":0.2,"memory":0.3,"connections":42,"protocolStats":[{"protocol":"VLESS","connections":4,"rxBps":100,"txBps":50},{"protocol":"tuic","connections":2,"rxBps":80,"txBps":30}]}`, headers, http.StatusOK)
	expectStatus(t, server, http.MethodGet, "/api/v1/nodes", "", headers, http.StatusOK)
	expectStatus(t, server, http.MethodGet, "/api/v1/nodes/node-1", "", headers, http.StatusOK)
	kernelRes := expectStatus(t, server, http.MethodGet, "/api/v1/nodes/kernel-tuning", "", headers, http.StatusOK)
	var kernelRows []NodeKernelTuning
	if err := json.Unmarshal(kernelRes.Body.Bytes(), &kernelRows); err != nil {
		t.Fatalf("decode kernel tuning response: %v", err)
	}
	if len(kernelRows) != 1 || !kernelRows[0].Tuned {
		t.Fatalf("unexpected kernel tuning response: %+v", kernelRows)
	}
	deployRes := expectStatus(t, server, http.MethodPost, "/api/v1/nodes/node-1/deploy-config", `{"content":"{\"global\":{\"route\":{\"final\":\"proxy-default\"}},\"nodes\":{\"node-1\":{\"outbound\":\"node-1-only\"},\"node-2\":{\"secret\":\"node-2-must-not-ship\"}}}"}`, headers, http.StatusOK)
	var deployment Deployment
	if err := json.Unmarshal(deployRes.Body.Bytes(), &deployment); err != nil {
		t.Fatalf("decode deployment response: %v", err)
	}
	if deployment.PayloadHash == "" || deployment.PayloadBytes == 0 {
		t.Fatalf("deployment response missing node payload metadata: %+v", deployment)
	}
	for _, forbidden := range []string{"node-1-only", "node-2-must-not-ship", "proxy-default"} {
		if strings.Contains(deployRes.Body.String(), forbidden) {
			t.Fatalf("deployment response leaked rendered payload content %q: %s", forbidden, deployRes.Body.String())
		}
	}
	expectStatus(t, server, http.MethodPost, "/api/v1/nodes/node-1/rollback", `{"version":1}`, headers, http.StatusOK)

	expectStatus(t, server, http.MethodGet, "/api/v1/rules", "", headers, http.StatusOK)
	expectStatus(t, server, http.MethodPost, "/api/v1/rules/compile", `{"warpInclude":["example-warp-target.com"]}`, headers, http.StatusOK)
	expectStatus(t, server, http.MethodGet, "/api/v1/rules/test-domain?input=scholar.google.com", "", headers, http.StatusOK)
	postDomainRes := expectStatus(t, server, http.MethodPost, "/api/v1/rules/test-domain", `{"input":"scholar.google.com"}`, headers, http.StatusOK)
	var postDomain rulecompiler.Classification
	if err := json.Unmarshal(postDomainRes.Body.Bytes(), &postDomain); err != nil {
		t.Fatalf("decode POST test-domain response: %v", err)
	}
	if postDomain.Outbound != rulecompiler.OutboundProxy || postDomain.MatchedSource != "warp-exclude-google-scholar" {
		t.Fatalf("POST test-domain returned unexpected classification: %+v", postDomain)
	}
	expectStatus(t, server, http.MethodPut, "/api/v1/rules/test-domain", `{"input":"scholar.google.com"}`, headers, http.StatusMethodNotAllowed)
	rulesPublishRes := expectStatus(t, server, http.MethodPost, "/api/v1/rules/publish", `{"warpInclude":["warp-only.example"],"rolloutPercent":20}`, headers, http.StatusOK)
	var rulesReport rulecompiler.DiffReport
	if err := json.Unmarshal(rulesPublishRes.Body.Bytes(), &rulesReport); err != nil {
		t.Fatalf("decode rules publish report: %v", err)
	}
	if len(rulesReport.HitChanges) == 0 {
		t.Fatalf("rules publish response missing hit changes: %s", rulesPublishRes.Body.String())
	}
	if rulesReport.Coverage.TotalSamples == 0 || len(rulesReport.Coverage.RuleHits) == 0 {
		t.Fatalf("rules publish response missing coverage analysis: %+v", rulesReport.Coverage)
	}
	if rulesReport.RolloutPercent != 20 {
		t.Fatalf("rules publish response missing rollout percent: %+v", rulesReport)
	}
	expectStatus(t, server, http.MethodPost, "/api/v1/rules/rollback", `{}`, headers, http.StatusOK)
	badRuleSet := expectStatus(t, server, http.MethodPost, "/api/v1/rules/rule-sets", `{"name":"bad","sourceUrl":"https://127.0.0.1/rules.srs","checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, headers, http.StatusBadRequest)
	if !strings.Contains(strings.ToLower(badRuleSet.Body.String()), "bad request") {
		t.Fatalf("bad rule set response should explain bad request: %s", badRuleSet.Body.String())
	}
	checksum := strings.Repeat("b", 64)
	ruleSetRes := expectStatus(t, server, http.MethodPost, "/api/v1/rules/rule-sets", `{"id":"ruleset-cn","name":"CN Direct","sourceUrl":"https://rules.example.com/cn.srs","checksum":"`+checksum+`"}`, headers, http.StatusOK)
	var ruleSet RuleSetSource
	if err := json.Unmarshal(ruleSetRes.Body.Bytes(), &ruleSet); err != nil {
		t.Fatalf("decode rule set source response: %v", err)
	}
	if ruleSet.ID != "ruleset-cn" || ruleSet.SourceURL != "https://rules.example.com/cn.srs" || ruleSet.Checksum != checksum {
		t.Fatalf("rule set source response mismatch: %+v", ruleSet)
	}
	expectStatus(t, server, http.MethodGet, "/api/v1/rules/rule-sets", "", headers, http.StatusOK)
	badWebhook := expectStatus(t, server, http.MethodPost, "/api/v1/webhooks/endpoints", `{"name":"bad","targetUrl":"https://127.0.0.1/events","eventTypes":["alert.created"],"signingSecret":"super-secret-webhook-value"}`, headers, http.StatusBadRequest)
	if strings.Contains(badWebhook.Body.String(), "super-secret") {
		t.Fatalf("bad webhook response leaked signing secret: %s", badWebhook.Body.String())
	}
	webhookRes := expectStatus(t, server, http.MethodPost, "/api/v1/webhooks/endpoints", `{"id":"webhook-1","name":"alerts","targetUrl":"https://hooks.example.com/events","eventTypes":["alert.created"],"signingSecret":"super-secret-webhook-value"}`, headers, http.StatusOK)
	var webhook WebhookEndpoint
	if err := json.Unmarshal(webhookRes.Body.Bytes(), &webhook); err != nil {
		t.Fatalf("decode webhook endpoint response: %v", err)
	}
	if webhook.ID != "webhook-1" || webhook.TargetURL != "https://hooks.example.com/events" || webhook.SigningSecretHash != "" {
		t.Fatalf("webhook endpoint response mismatch or leaked hash: %+v", webhook)
	}
	if strings.Contains(webhookRes.Body.String(), "super-secret") || strings.Contains(webhookRes.Body.String(), "SigningSecretHash") {
		t.Fatalf("webhook response leaked signing secret: %s", webhookRes.Body.String())
	}
	expectStatus(t, server, http.MethodGet, "/api/v1/webhooks/endpoints", "", headers, http.StatusOK)

	badConversion := expectStatus(t, server, http.MethodPost, "/api/v1/subscriptions/conversions", `{"name":"bad","sourceUrl":"https://127.0.0.1/sub.txt?token=secret","sourceChecksum":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","targetClientType":"sing-box"}`, headers, http.StatusBadRequest)
	if strings.Contains(badConversion.Body.String(), "secret") {
		t.Fatalf("bad subscription conversion response leaked query secret: %s", badConversion.Body.String())
	}
	conversionRes := expectStatus(t, server, http.MethodPost, "/api/v1/subscriptions/conversions", `{"id":"subconv-1","name":"convert","sourceUrl":"https://subs.example.com/user.txt","sourceChecksum":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","sourceClientType":"clash-meta","targetClientType":"sing-box","deviceId":"phone-01","region":"HK","protocol":"tuic","outboundPolicy":"warp-pool"}`, headers, http.StatusOK)
	var conversion SubscriptionConversion
	if err := json.Unmarshal(conversionRes.Body.Bytes(), &conversion); err != nil {
		t.Fatalf("decode subscription conversion response: %v", err)
	}
	if conversion.ID != "subconv-1" || conversion.SourceURL != "https://subs.example.com/user.txt" || conversion.TargetClientType != "sing-box" || conversion.Protocol != "tuic" {
		t.Fatalf("subscription conversion response mismatch: %+v", conversion)
	}
	expectStatus(t, server, http.MethodGet, "/api/v1/subscriptions/conversions", "", headers, http.StatusOK)

	subRes := expectStatus(t, server, http.MethodPost, "/api/v1/subscriptions", `{"userId":"user-1","clientType":"sing-box","policyId":"policy-warp","deviceId":"phone-01","region":"HK","protocol":"tuic","outboundPolicy":"warp-pool","tokenKind":"one-time","scope":"read","usesRemaining":1,"ipAllowlist":["192.0.2.1"]}`, headers, http.StatusOK)
	var subBody struct {
		Token        string `json:"token"`
		Subscription struct {
			DeviceID       string `json:"deviceId"`
			Region         string `json:"region"`
			Protocol       string `json:"protocol"`
			OutboundPolicy string `json:"outboundPolicy"`
			PolicyID       string `json:"policyId"`
		} `json:"subscription"`
	}
	if err := json.Unmarshal(subRes.Body.Bytes(), &subBody); err != nil {
		t.Fatalf("decode subscription response: %v", err)
	}
	if subBody.Token == "" || strings.Contains(subRes.Body.String(), "TokenHash") {
		t.Fatalf("subscription create did not return safe token response: %s", subRes.Body.String())
	}
	if subBody.Subscription.DeviceID != "phone-01" || subBody.Subscription.Region != "HK" || subBody.Subscription.Protocol != "tuic" || subBody.Subscription.OutboundPolicy != "warp-pool" || subBody.Subscription.PolicyID != "policy-warp" {
		t.Fatalf("subscription response missing context: %+v", subBody.Subscription)
	}
	expectStatus(t, server, http.MethodGet, "/api/v1/subscriptions", "", headers, http.StatusOK)

	profileRes := expectStatus(t, server, http.MethodPost, "/api/v1/warp/profiles", `{"id":"warp-1","name":"warp-01","publicKey":"pub","encryptedPrivateKey":"encrypted"}`, headers, http.StatusOK)
	if strings.Contains(profileRes.Body.String(), "encrypted") {
		t.Fatalf("warp private material leaked: %s", profileRes.Body.String())
	}
	expectStatus(t, server, http.MethodPost, "/api/v1/warp/profiles/warp-1/probe", `{"latencyMs":58,"loss":0,"httpSuccess":true,"exitIP":"203.0.113.1","asn":"AS13335","ipv4":true,"ipv6":true}`, headers, http.StatusOK)
	expectStatus(t, server, http.MethodGet, "/api/v1/warp/profiles", "", headers, http.StatusOK)
	expectStatus(t, server, http.MethodPost, "/api/v1/warp/profiles/warp-1/disable", `{}`, headers, http.StatusOK)
	wireGuardConfig := `[Interface]
PrivateKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
Address = 172.16.0.3/32
DNS = 1.1.1.1

[Peer]
PublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
`
	wireGuardReq, err := json.Marshal(WarpWireGuardImport{ID: "warp-import", Name: "wg-import", Config: wireGuardConfig})
	if err != nil {
		t.Fatalf("marshal wireguard import: %v", err)
	}
	importRes := expectStatus(t, server, http.MethodPost, "/api/v1/warp/profiles/import-wireguard", string(wireGuardReq), headers, http.StatusOK)
	if strings.Contains(importRes.Body.String(), "CCCCCCCC") || strings.Contains(importRes.Body.String(), "EncryptedPrivateKey") {
		t.Fatalf("wireguard import response leaked private key: %s", importRes.Body.String())
	}
	var importedWarp WarpProfile
	if err := json.Unmarshal(importRes.Body.Bytes(), &importedWarp); err != nil {
		t.Fatalf("decode wireguard import response: %v", err)
	}
	if importedWarp.Endpoint != "engage.cloudflareclient.com:2408" || len(importedWarp.AllowedIPs) != 2 {
		t.Fatalf("wireguard import response incomplete: %+v", importedWarp)
	}

	argoRes := expectStatus(t, server, http.MethodPost, "/api/v1/argo/tunnels", `{"id":"argo-1","name":"panel","hostname":"panel.example.com","serviceUrl":"http://127.0.0.1:8080?token=secret","tunnelId":"tunnel-01"}`, headers, http.StatusOK)
	var argo ArgoTunnel
	if err := json.Unmarshal(argoRes.Body.Bytes(), &argo); err != nil {
		t.Fatalf("decode Argo tunnel response: %v", err)
	}
	if argo.ID != "argo-1" || argo.ServiceURL != "http://127.0.0.1:8080" {
		t.Fatalf("Argo tunnel response not normalized: %+v", argo)
	}
	expectStatus(t, server, http.MethodGet, "/api/v1/argo/tunnels", "", headers, http.StatusOK)
	argoConfig := expectStatus(t, server, http.MethodGet, "/api/v1/argo/tunnels/argo-1/config", "", headers, http.StatusOK)
	if !strings.Contains(argoConfig.Body.String(), "hostname: panel.example.com") || strings.Contains(argoConfig.Body.String(), "secret") {
		t.Fatalf("Argo config unsafe or incomplete: %s", argoConfig.Body.String())
	}
	cfPlanRes := expectStatus(t, server, http.MethodPost, "/api/v1/argo/cloudflare/automation-plan", `{"name":"panel","hostname":"panel.example.com","serviceUrl":"http://127.0.0.1:8080?token=secret","cloudflareAccountId":"0123456789abcdef0123456789abcdef","cloudflareZoneId":"abcdef0123456789abcdef0123456789"}`, headers, http.StatusOK)
	var cfPlan CloudflareArgoAutomationPlan
	if err := json.Unmarshal(cfPlanRes.Body.Bytes(), &cfPlan); err != nil {
		t.Fatalf("decode Cloudflare Argo plan: %v", err)
	}
	if len(cfPlan.Operations) != 3 || cfPlan.Tunnel.ServiceURL != "http://127.0.0.1:8080" {
		t.Fatalf("Cloudflare Argo plan incomplete: %+v", cfPlan)
	}
	if strings.Contains(cfPlanRes.Body.String(), "secret") || strings.Contains(cfPlanRes.Body.String(), "Authorization") {
		t.Fatalf("Cloudflare Argo plan leaked secret material: %s", cfPlanRes.Body.String())
	}

	badMetric := expectStatus(t, server, http.MethodPost, "/api/v1/metrics/nodes/node-1", `{"nodeId":"node-other","connections":1}`, headers, http.StatusBadRequest)
	if strings.Contains(badMetric.Body.String(), "node-other") {
		t.Fatalf("bad metric response reflected mismatched node id: %s", badMetric.Body.String())
	}
	metricRes := expectStatus(t, server, http.MethodPost, "/api/v1/metrics/nodes/node-1", `{"cpu":1.2,"memory":0.4,"rxBps":128,"txBps":256,"rxBytes":1024,"txBytes":2048,"networkPPS":12,"connections":17}`, headers, http.StatusOK)
	var metric NodeMetricSample
	if err := json.Unmarshal(metricRes.Body.Bytes(), &metric); err != nil {
		t.Fatalf("decode metric response: %v", err)
	}
	if metric.NodeID != "node-1" || metric.CPU != 1 || metric.RxBps != 128 {
		t.Fatalf("metric response not normalized: %+v", metric)
	}
	metricsRes := expectStatus(t, server, http.MethodGet, "/api/v1/metrics/nodes/node-1?limit=1", "", headers, http.StatusOK)
	var samples []NodeMetricSample
	if err := json.Unmarshal(metricsRes.Body.Bytes(), &samples); err != nil {
		t.Fatalf("decode metrics response: %v", err)
	}
	if len(samples) != 1 || samples[0].Connections != 17 {
		t.Fatalf("unexpected metrics response: %+v", samples)
	}
	protocolStatsRes := expectStatus(t, server, http.MethodGet, "/api/v1/protocols/stats", "", headers, http.StatusOK)
	var protocolStats []ProtocolInboundStat
	if err := json.Unmarshal(protocolStatsRes.Body.Bytes(), &protocolStats); err != nil {
		t.Fatalf("decode protocol stats response: %v", err)
	}
	if len(protocolStats) != 2 || protocolStats[0].Protocol != "vless" || protocolStats[1].Protocol != "tuic" {
		t.Fatalf("unexpected protocol stats response: %+v", protocolStats)
	}
	expectStatus(t, server, http.MethodGet, "/api/v1/metrics/overview", "", headers, http.StatusOK)
	capacityRes := expectStatus(t, server, http.MethodGet, "/api/v1/metrics/capacity", "", headers, http.StatusOK)
	var capacity CapacityRecommendation
	if err := json.Unmarshal(capacityRes.Body.Bytes(), &capacity); err != nil {
		t.Fatalf("decode capacity response: %v", err)
	}
	if capacity.TenantID != "tenant-a" || capacity.RecommendedAPIReplicas == 0 || len(capacity.AutoscalingActions) == 0 {
		t.Fatalf("capacity response incomplete: %+v", capacity)
	}
	expectStatus(t, server, http.MethodGet, "/api/v1/metrics/dependencies", "", headers, http.StatusOK)
	expectStatus(t, server, http.MethodGet, "/api/v1/logs", "", headers, http.StatusOK)
	expectStatus(t, server, http.MethodGet, "/api/v1/audit-logs", "", headers, http.StatusOK)
	cp.mu.Lock()
	cp.alerts = append(cp.alerts, Alert{ID: "alert-http", TenantID: "tenant-a", NodeID: "node-1", Severity: "P2", Message: `<script>alert(1)</script> token=secret`, CreatedAt: time.Now()})
	cp.mu.Unlock()
	alertsRes := expectStatus(t, server, http.MethodGet, "/api/v1/alerts", "", headers, http.StatusOK)
	if strings.Contains(alertsRes.Body.String(), "<script>") || strings.Contains(alertsRes.Body.String(), "secret") {
		t.Fatalf("alert API response unsafe: %s", alertsRes.Body.String())
	}
	alertAckRes := expectStatus(t, server, http.MethodPost, "/api/v1/alerts/alert-http/ack", `{}`, headers, http.StatusOK)
	var ack Alert
	if err := json.Unmarshal(alertAckRes.Body.Bytes(), &ack); err != nil {
		t.Fatalf("decode alert ack: %v", err)
	}
	if ack.Status != alertStatusAcknowledged {
		t.Fatalf("alert ack response status=%q", ack.Status)
	}
	waiverRes := expectStatus(t, server, http.MethodPost, "/api/v1/security/waivers", `{"id":"waiver-http","gate":"DAST","severity":"P2","owner":"sec@example.com","reason":"scanner outage token=secret","remediationPlan":"rerun staging DAST","expiresAt":"2026-06-04T12:00:00Z"}`, headers, http.StatusOK)
	if strings.Contains(waiverRes.Body.String(), "secret") {
		t.Fatalf("security waiver response leaked secret: %s", waiverRes.Body.String())
	}
	var waiver SecurityWaiver
	if err := json.Unmarshal(waiverRes.Body.Bytes(), &waiver); err != nil {
		t.Fatalf("decode security waiver: %v", err)
	}
	if waiver.Owner == "" || waiver.RemediationPlan == "" || !waiver.ExpiresAt.After(now) {
		t.Fatalf("security waiver missing required fields: %+v", waiver)
	}
	expectStatus(t, server, http.MethodGet, "/api/v1/security/waivers", "", headers, http.StatusOK)
	expectStatus(t, server, http.MethodGet, "/api/v1/incidents", "", headers, http.StatusOK)
	runbooksRes := expectStatus(t, server, http.MethodGet, "/api/v1/incidents/runbooks", "", headers, http.StatusOK)
	var runbooks []RunbookDefinition
	if err := json.Unmarshal(runbooksRes.Body.Bytes(), &runbooks); err != nil {
		t.Fatalf("decode runbook catalog: %v", err)
	}
	for _, severity := range []string{"P0", "P1", "P2", "P3"} {
		if !runbookCatalogHasSeverity(runbooks, severity) {
			t.Fatalf("runbook API missing %s coverage: %+v", severity, runbooks)
		}
	}
	expectStatus(t, server, http.MethodPost, "/api/v1/incidents/inc-1/runbook/rollback-config", `{}`, headers, http.StatusOK)
}

func TestHTTPNodeABACHeadersFilterAdminEndpoints(t *testing.T) {
	cp := New(nil)
	server := NewHTTPHandler(cp)
	headers := map[string]string{"X-User-ID": "admin", "X-Tenant-ID": "tenant-a", "X-Role": string(RoleAdmin), "X-Confirm-Token": ConfirmationToken("admin")}
	expectStatus(t, server, http.MethodPost, "/api/v1/nodes/register", `{"id":"node-hk-prod","tenantId":"tenant-a","region":"HK","tags":["edge","warp"],"environment":"prod"}`, headers, http.StatusOK)
	expectStatus(t, server, http.MethodPost, "/api/v1/nodes/register", `{"id":"node-us-dev","tenantId":"tenant-a","region":"US","tags":["edge"],"environment":"dev"}`, headers, http.StatusOK)

	restricted := map[string]string{}
	for key, value := range headers {
		restricted[key] = value
	}
	restricted["X-ABAC-Regions"] = "hk"
	restricted["X-ABAC-Node-Tags"] = "warp"
	restricted["X-ABAC-Environments"] = "PROD"

	listRes := expectStatus(t, server, http.MethodGet, "/api/v1/nodes", "", restricted, http.StatusOK)
	var nodes []Node
	if err := json.Unmarshal(listRes.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode restricted node list: %v", err)
	}
	if len(nodes) != 1 || nodes[0].ID != "node-hk-prod" {
		t.Fatalf("restricted HTTP list returned %+v, want only node-hk-prod", nodes)
	}
	expectStatus(t, server, http.MethodGet, "/api/v1/nodes/node-hk-prod", "", restricted, http.StatusOK)
	expectStatus(t, server, http.MethodGet, "/api/v1/nodes/node-us-dev", "", restricted, http.StatusForbidden)
	expectStatus(t, server, http.MethodPost, "/api/v1/nodes/node-us-dev/heartbeat", `{"connections":1}`, restricted, http.StatusForbidden)
}

func TestHTTPRouteDecisionTraceExplainsRuleHit(t *testing.T) {
	cp := New(nil)
	server := NewHTTPHandler(cp)
	headers := map[string]string{"X-User-ID": "admin", "X-Tenant-ID": "tenant-a", "X-Role": string(RoleAdmin), "X-Confirm-Token": ConfirmationToken("admin")}

	traceRes := expectStatus(t, server, http.MethodPost, "/api/v1/routes/trace", `{"input":"https://www.taobao.com/path?token=secret","protocol":"vless","clientIP":"198.51.100.10"}`, headers, http.StatusOK)
	if strings.Contains(traceRes.Body.String(), "secret") {
		t.Fatalf("route trace leaked raw query string: %s", traceRes.Body.String())
	}
	var trace RouteDecisionTrace
	if err := json.Unmarshal(traceRes.Body.Bytes(), &trace); err != nil {
		t.Fatalf("decode route trace: %v", err)
	}
	if trace.Input != "www.taobao.com" || trace.Outbound != rulecompiler.OutboundDirect || trace.MatchedSource != "builtin-geosite-cn" || trace.Decision == "" {
		t.Fatalf("unexpected route trace: %+v", trace)
	}
	tracesRes := expectStatus(t, server, http.MethodGet, "/api/v1/routes/traces?limit=1", "", headers, http.StatusOK)
	var traces []RouteDecisionTrace
	if err := json.Unmarshal(tracesRes.Body.Bytes(), &traces); err != nil {
		t.Fatalf("decode route trace list: %v", err)
	}
	if len(traces) != 1 || traces[0].ID != trace.ID {
		t.Fatalf("unexpected route trace list: %+v", traces)
	}
}

func TestSubscriptionTokenKindsAllowlistAndETag(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	_, token, err := cp.CreateSubscriptionWithOptions(ctx, "tenant-a", "user-1", "sing-box", "policy-1", now.Add(time.Hour), SubscriptionOptions{
		TokenKind:     "one-time",
		Scope:         "read",
		IPAllowlist:   []string{"192.0.2.10"},
		UsesRemaining: 1,
	})
	if err != nil {
		t.Fatalf("create one-time token: %v", err)
	}
	if _, err := cp.RenderSubscription(token, "sing-box", "192.0.2.11"); err == nil {
		t.Fatal("IP allowlist did not reject unauthorized subscription access")
	}
	if _, err := cp.RenderSubscription(token, "sing-box", "192.0.2.10"); err != nil {
		t.Fatalf("authorized one-time render failed: %v", err)
	}
	if _, err := cp.RenderSubscription(token, "sing-box", "192.0.2.10"); err != ErrRevoked {
		t.Fatalf("one-time token second use err=%v, want revoked", err)
	}

	_, cacheToken, err := cp.CreateSubscription(ctx, "tenant-a", "user-2", "sing-box", "policy-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("create cache token: %v", err)
	}
	server := NewHTTPHandler(cp)
	first := httptest.NewRecorder()
	server.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/sub/"+cacheToken+"/sing-box", nil))
	if first.Code != http.StatusOK || first.Header().Get("ETag") == "" || first.Header().Get("Last-Modified") == "" {
		t.Fatalf("subscription cache headers missing: status=%d headers=%v", first.Code, first.Header())
	}
	if first.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("subscription response missing Accept-Encoding vary header: %v", first.Header())
	}
	secondReq := httptest.NewRequest(http.MethodGet, "/sub/"+cacheToken+"/sing-box", nil)
	secondReq.Header.Set("If-None-Match", first.Header().Get("ETag"))
	second := httptest.NewRecorder()
	server.ServeHTTP(second, secondReq)
	if second.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match status=%d, want 304", second.Code)
	}

	gzipReq := httptest.NewRequest(http.MethodGet, "/sub/"+cacheToken+"/sing-box", nil)
	gzipReq.Header.Set("Accept-Encoding", "gzip")
	gzipRes := httptest.NewRecorder()
	server.ServeHTTP(gzipRes, gzipReq)
	if gzipRes.Code != http.StatusOK || gzipRes.Header().Get("Content-Encoding") != "gzip" || gzipRes.Header().Get("ETag") == "" {
		t.Fatalf("gzip subscription response invalid: status=%d headers=%v", gzipRes.Code, gzipRes.Header())
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(gzipRes.Body.Bytes()))
	if err != nil {
		t.Fatalf("open gzip response: %v", err)
	}
	gzipPlain, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("read gzip response: %v", err)
	}
	if err := gzipReader.Close(); err != nil {
		t.Fatalf("close gzip response: %v", err)
	}
	if string(gzipPlain) != first.Body.String() {
		t.Fatalf("gzip body changed subscription content: %q != %q", string(gzipPlain), first.Body.String())
	}

	brReq := httptest.NewRequest(http.MethodGet, "/sub/"+cacheToken+"/sing-box", nil)
	brReq.Header.Set("Accept-Encoding", "br, gzip")
	brRes := httptest.NewRecorder()
	server.ServeHTTP(brRes, brReq)
	if brRes.Code != http.StatusOK || brRes.Header().Get("Content-Encoding") != "br" {
		t.Fatalf("brotli subscription response invalid: status=%d headers=%v", brRes.Code, brRes.Header())
	}
	brPlain, err := io.ReadAll(brotli.NewReader(bytes.NewReader(brRes.Body.Bytes())))
	if err != nil {
		t.Fatalf("read brotli response: %v", err)
	}
	if string(brPlain) != first.Body.String() {
		t.Fatalf("brotli body changed subscription content: %q != %q", string(brPlain), first.Body.String())
	}
}

func TestHTTPBearerAPITokenScopesAndIPAllowlist(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	ctx := adminCtx("tenant-a")
	_, token, err := cp.CreateAPIToken(ctx, "tenant-a", RoleAdmin, []string{"rules:read"}, []string{"192.0.2.99"}, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("create API token: %v", err)
	}
	server := NewHTTPHandler(cp)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/test-domain?input=www.taobao.com", nil)
	req.RemoteAddr = "192.0.2.99:12345"
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("bearer rules read status=%d body=%s", res.Code, res.Body.String())
	}

	writeReq := httptest.NewRequest(http.MethodPost, "/api/v1/rules/publish", bytes.NewBufferString(`{"warpInclude":["warp-only.example"]}`))
	writeReq.RemoteAddr = "192.0.2.99:12345"
	writeReq.Header.Set("Authorization", "Bearer "+token)
	writeReq.Header.Set("Content-Type", "application/json")
	writeReq.Header.Set("X-Confirm-Token", ConfirmationToken("admin-tenant-a"))
	writeRes := httptest.NewRecorder()
	server.ServeHTTP(writeRes, writeReq)
	if writeRes.Code != http.StatusForbidden {
		t.Fatalf("bearer write status=%d want 403 body=%s", writeRes.Code, writeRes.Body.String())
	}

	badIP := httptest.NewRequest(http.MethodGet, "/api/v1/rules/test-domain?input=www.taobao.com", nil)
	badIP.RemoteAddr = "192.0.2.100:12345"
	badIP.Header.Set("Authorization", "Bearer "+token)
	badRes := httptest.NewRecorder()
	server.ServeHTTP(badRes, badIP)
	if badRes.Code < http.StatusBadRequest {
		t.Fatalf("bearer IP allowlist status=%d should reject body=%s", badRes.Code, badRes.Body.String())
	}
}

func TestHTTPAgentMTLSFingerprintOnlyAllowsHeartbeat(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	server := NewHTTPHandler(cp)
	headers := map[string]string{"X-User-ID": "admin", "X-Tenant-ID": "tenant-a", "X-Role": string(RoleAdmin), "X-Confirm-Token": ConfirmationToken("admin")}
	expectStatus(t, server, http.MethodPost, "/api/v1/nodes/register", `{"id":"node-agent","tenantId":"tenant-a","name":"agent-node"}`, headers, http.StatusOK)

	credentialRes := expectStatus(t, server, http.MethodPost, "/api/v1/nodes/node-agent/agent-credential", `{}`, headers, http.StatusOK)
	var credentialBody struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(credentialRes.Body.Bytes(), &credentialBody); err != nil {
		t.Fatalf("decode credential response: %v", err)
	}
	if credentialBody.Fingerprint == "" || strings.Contains(credentialRes.Body.String(), "FingerprintHash") {
		t.Fatalf("unsafe credential response: %s", credentialRes.Body.String())
	}

	agentHeaders := map[string]string{"X-Agent-Node-ID": "node-agent", "X-Agent-Cert-SHA256": credentialBody.Fingerprint}
	expectStatus(t, server, http.MethodPost, "/api/v1/nodes/node-agent/heartbeat", `{"agentVersion":"mtls-agent","connections":9}`, agentHeaders, http.StatusOK)
	expectStatus(t, server, http.MethodGet, "/api/v1/nodes/node-agent", "", agentHeaders, http.StatusUnauthorized)

	mismatch := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/node-agent/heartbeat", bytes.NewBufferString(`{}`))
	mismatch.Header.Set("Content-Type", "application/json")
	mismatch.Header.Set("X-Agent-Node-ID", "other-node")
	mismatch.Header.Set("X-Agent-Cert-SHA256", credentialBody.Fingerprint)
	mismatchRes := httptest.NewRecorder()
	server.ServeHTTP(mismatchRes, mismatch)
	if mismatchRes.Code != http.StatusForbidden {
		t.Fatalf("mismatched agent node status=%d want 403 body=%s", mismatchRes.Code, mismatchRes.Body.String())
	}

	ctx := adminCtx("tenant-a")
	_, token, err := cp.CreateAPIToken(ctx, "tenant-a", RoleAdmin, []string{"rules:read"}, []string{"192.0.2.99"}, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("create scoped API token: %v", err)
	}
	scopedReq := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/node-agent/heartbeat", bytes.NewBufferString(`{}`))
	scopedReq.RemoteAddr = "192.0.2.99:12345"
	scopedReq.Header.Set("Authorization", "Bearer "+token)
	scopedReq.Header.Set("Content-Type", "application/json")
	scopedRes := httptest.NewRecorder()
	server.ServeHTTP(scopedRes, scopedReq)
	if scopedRes.Code != http.StatusForbidden {
		t.Fatalf("scoped bearer heartbeat status=%d want 403 body=%s", scopedRes.Code, scopedRes.Body.String())
	}
}

func TestHTTPPasskeyRegistrationAndAuthenticationFlow(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	server := NewHTTPHandler(cp)
	headers := map[string]string{"X-User-ID": "admin", "X-Tenant-ID": "tenant-a", "X-Role": string(RoleAdmin), "X-Confirm-Token": ConfirmationToken("admin")}

	optionsRes := expectStatus(t, server, http.MethodPost, "/api/v1/auth/passkeys/register-options", `{"rpId":"example.com","origin":"https://panel.example.com"}`, headers, http.StatusOK)
	var options struct {
		ChallengeID string `json:"challengeId"`
		Challenge   string `json:"challenge"`
	}
	if err := json.Unmarshal(optionsRes.Body.Bytes(), &options); err != nil {
		t.Fatalf("decode register options: %v", err)
	}
	if options.ChallengeID == "" || options.Challenge == "" || strings.Contains(optionsRes.Body.String(), "ChallengeHash") {
		t.Fatalf("unsafe passkey options response: %s", optionsRes.Body.String())
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate passkey key: %v", err)
	}
	encodedPublicKey, err := EncodePasskeyPublicKey(privateKey.PublicKey)
	if err != nil {
		t.Fatalf("encode passkey public key: %v", err)
	}
	registerBody, err := json.Marshal(map[string]any{
		"challengeId":  options.ChallengeID,
		"challenge":    options.Challenge,
		"credentialId": "cred-http",
		"publicKey":    encodedPublicKey,
		"signCount":    1,
	})
	if err != nil {
		t.Fatalf("encode register body: %v", err)
	}
	registerRes := expectStatus(t, server, http.MethodPost, "/api/v1/auth/passkeys/register", string(registerBody), headers, http.StatusOK)
	if strings.Contains(registerRes.Body.String(), encodedPublicKey) {
		t.Fatalf("passkey register response leaked public key payload: %s", registerRes.Body.String())
	}

	authOptionsRes := expectStatus(t, server, http.MethodPost, "/api/v1/auth/passkeys/authentication-options", `{"userId":"admin","credentialId":"cred-http","rpId":"example.com","origin":"https://panel.example.com"}`, nil, http.StatusOK)
	var authOptions struct {
		ChallengeID string `json:"challengeId"`
		Challenge   string `json:"challenge"`
	}
	if err := json.Unmarshal(authOptionsRes.Body.Bytes(), &authOptions); err != nil {
		t.Fatalf("decode auth options: %v", err)
	}
	signCount := uint32(2)
	hash := PasskeySignatureHash(authOptions.Challenge, "example.com", "https://panel.example.com", "admin", "cred-http", signCount)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash)
	if err != nil {
		t.Fatalf("sign passkey assertion: %v", err)
	}
	authBody, err := json.Marshal(map[string]any{
		"challengeId": authOptions.ChallengeID,
		"challenge":   authOptions.Challenge,
		"signature":   base64.RawURLEncoding.EncodeToString(signature),
		"signCount":   signCount,
	})
	if err != nil {
		t.Fatalf("encode auth body: %v", err)
	}
	authRes := expectStatus(t, server, http.MethodPost, "/api/v1/auth/passkeys/authenticate", string(authBody), nil, http.StatusOK)
	if !strings.Contains(authRes.Body.String(), `"authenticated":true`) || !strings.Contains(authRes.Body.String(), `"tenantId":"tenant-a"`) {
		t.Fatalf("passkey auth response missing context: %s", authRes.Body.String())
	}
}

func TestHTTPRateLimitsLoginAgentRegistrationAndConfigDeploy(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := New(func() time.Time { return now })
	server := NewHTTPHandler(cp)
	headers := map[string]string{"X-User-ID": "admin", "X-Tenant-ID": "tenant-a", "X-Role": string(RoleAdmin), "X-Confirm-Token": ConfirmationToken("admin")}

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/register", bytes.NewBufferString(`{"id":"node-rate-`+string(rune('a'+i))+`","tenantId":"tenant-a"}`))
		req.RemoteAddr = "203.0.113.20:12345"
		req.Header.Set("Content-Type", "application/json")
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		res := httptest.NewRecorder()
		server.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("agent register %d status=%d body=%s", i, res.Code, res.Body.String())
		}
	}
	limitedRegister := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/register", bytes.NewBufferString(`{"id":"node-rate-over","tenantId":"tenant-a"}`))
	limitedRegister.RemoteAddr = "203.0.113.20:12345"
	limitedRegister.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		limitedRegister.Header.Set(key, value)
	}
	limitedRegisterRes := httptest.NewRecorder()
	server.ServeHTTP(limitedRegisterRes, limitedRegister)
	if limitedRegisterRes.Code != http.StatusTooManyRequests {
		t.Fatalf("agent register limit status=%d want 429 body=%s", limitedRegisterRes.Code, limitedRegisterRes.Body.String())
	}

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/authentication-options", bytes.NewBufferString(`{"userId":"missing","credentialId":"missing","rpId":"example.com","origin":"https://panel.example.com"}`))
		req.RemoteAddr = "203.0.113.30:12345"
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		server.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("login attempt %d status=%d want 401 body=%s", i, res.Code, res.Body.String())
		}
	}
	limitedLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/authentication-options", bytes.NewBufferString(`{"userId":"missing","credentialId":"missing","rpId":"example.com","origin":"https://panel.example.com"}`))
	limitedLogin.RemoteAddr = "203.0.113.30:12345"
	limitedLogin.Header.Set("Content-Type", "application/json")
	limitedLoginRes := httptest.NewRecorder()
	server.ServeHTTP(limitedLoginRes, limitedLogin)
	if limitedLoginRes.Code != http.StatusTooManyRequests {
		t.Fatalf("login limit status=%d want 429 body=%s", limitedLoginRes.Code, limitedLoginRes.Body.String())
	}

	expectStatus(t, server, http.MethodPost, "/api/v1/nodes/register", `{"id":"node-deploy-limit","tenantId":"tenant-a"}`, headers, http.StatusOK)
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/node-deploy-limit/deploy-config", bytes.NewBufferString(`{"content":"{\"version\":`+string(rune('0'+(i%10)))+`}"} `))
		req.RemoteAddr = "203.0.113.40:12345"
		req.Header.Set("Content-Type", "application/json")
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		res := httptest.NewRecorder()
		server.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("deploy %d status=%d body=%s", i, res.Code, res.Body.String())
		}
	}
	limitedDeploy := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/node-deploy-limit/deploy-config", bytes.NewBufferString(`{"content":"{}"}`))
	limitedDeploy.RemoteAddr = "203.0.113.40:12345"
	limitedDeploy.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		limitedDeploy.Header.Set(key, value)
	}
	limitedDeployRes := httptest.NewRecorder()
	server.ServeHTTP(limitedDeployRes, limitedDeploy)
	if limitedDeployRes.Code != http.StatusTooManyRequests {
		t.Fatalf("deploy limit status=%d want 429 body=%s", limitedDeployRes.Code, limitedDeployRes.Body.String())
	}
}

func TestPasskeyLoginPathsBypassCSRFOnlyForAllowedOrigins(t *testing.T) {
	cp := New(nil)
	server := NewHTTPHandler(cp)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/authentication-options", bytes.NewBufferString(`{"userId":"missing","credentialId":"missing","rpId":"example.com","origin":"https://panel.example.com"}`))
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("passkey login without csrf status=%d want 401 body=%s", res.Code, res.Body.String())
	}

	registerReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkeys/register-options", bytes.NewBufferString(`{"rpId":"example.com","origin":"https://panel.example.com"}`))
	registerReq.Header.Set("Origin", "http://127.0.0.1:8080")
	registerReq.Header.Set("Content-Type", "application/json")
	registerReq.Header.Set("X-User-ID", "admin")
	registerReq.Header.Set("X-Tenant-ID", "tenant-a")
	registerReq.Header.Set("X-Role", string(RoleAdmin))
	registerReq.Header.Set("X-Confirm-Token", ConfirmationToken("admin"))
	registerRes := httptest.NewRecorder()
	server.ServeHTTP(registerRes, registerReq)
	if registerRes.Code != http.StatusForbidden {
		t.Fatalf("passkey registration without csrf status=%d want 403 body=%s", registerRes.Code, registerRes.Body.String())
	}
}

func expectStatus(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string, status int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != status {
		t.Fatalf("%s %s status=%d want %d body=%s", method, path, res.Code, status, res.Body.String())
	}
	return res
}

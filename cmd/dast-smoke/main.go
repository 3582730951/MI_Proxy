package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"sing-box-next-panel/services/controlplane"
)

type check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type report struct {
	Checks []check `json:"checks"`
	Passed bool    `json:"passed"`
	Mode   string  `json:"mode"`
}

func main() {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	cp := controlplane.New(func() time.Time { return now })
	ctx := controlplane.RequestContext{User: controlplane.User{ID: "admin", TenantID: "tenant-a", Role: controlplane.RoleAdmin}, Confirmed: true}
	_, token, err := cp.CreateSubscription(ctx, "tenant-a", "user-1", "sing-box", "policy-1", now.Add(time.Hour))
	if err != nil {
		panic(err)
	}
	handler := controlplane.NewHTTPHandler(cp)
	result := report{Mode: "local-dast-smoke", Passed: true}

	result.add("unauthenticated admin API denied", request(handler, http.MethodPost, "/api/v1/nodes/register", "", nil).Code == http.StatusUnauthorized, "POST /api/v1/nodes/register")

	authHeaders := map[string]string{"X-User-ID": "admin", "X-Tenant-ID": "tenant-a", "X-Role": string(controlplane.RoleAdmin), "X-Confirm-Token": controlplane.ConfirmationToken("admin")}
	node := request(handler, http.MethodPost, "/api/v1/nodes/register", `{"id":"node-dast","tenantId":"tenant-a","region":"HK"}`, authHeaders)
	result.add("authenticated node registration available", node.Code == http.StatusOK, "POST /api/v1/nodes/register")
	res := request(handler, http.MethodGet, "/api/v1/rules/test-domain?input=%3Cscript%3Ealert(1)%3C/script%3E", "", authHeaders)
	body := res.Body.String()
	result.add("xss payload json escaped", res.Code == http.StatusOK && !strings.Contains(body, "<script>"), body)
	result.add("security headers present", hasSecurityHeaders(res), "CSP/nosniff/frame/referrer")

	sub := request(handler, http.MethodGet, "/sub/"+token+"/sing-box", "", nil)
	result.add("subscription token not reflected", sub.Code == http.StatusOK && !strings.Contains(sub.Body.String(), token), "GET /sub/{token}/sing-box")

	missing := request(handler, http.MethodGet, "/sub/not-a-token/sing-box", "", nil)
	result.add("invalid subscription token rejected", missing.Code == http.StatusNotFound, "GET /sub/not-a-token/sing-box")
	conversionSSRF := request(handler, http.MethodPost, "/api/v1/subscriptions/conversions", `{"name":"bad","sourceUrl":"https://169.254.169.254/latest/meta-data","sourceChecksum":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","targetClientType":"sing-box"}`, authHeaders)
	result.add("subscription conversion SSRF target blocked", conversionSSRF.Code == http.StatusBadRequest, "POST /api/v1/subscriptions/conversions metadata")
	conversionSecret := request(handler, http.MethodPost, "/api/v1/subscriptions/conversions", `{"name":"bad","sourceUrl":"https://subs.example.com/user.txt?token=secret","sourceChecksum":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","targetClientType":"sing-box"}`, authHeaders)
	result.add("subscription conversion URL secret not reflected", conversionSecret.Code == http.StatusBadRequest && !strings.Contains(conversionSecret.Body.String(), "secret"), "POST /api/v1/subscriptions/conversions query")

	traversal := request(handler, http.MethodGet, "/api/v1/logs?file=../../windows/win.ini", "", authHeaders)
	result.add("path traversal smoke has no 5xx", traversal.Code < 500, "GET /api/v1/logs?file=../../")

	ssrf := request(handler, http.MethodPost, "/api/v1/rules/rule-sets", `{"name":"bad","sourceUrl":"https://127.0.0.1/rules.srs","checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, authHeaders)
	result.add("rule source SSRF target blocked", ssrf.Code == http.StatusBadRequest, "POST /api/v1/rules/rule-sets localhost")
	webhookSSRF := request(handler, http.MethodPost, "/api/v1/webhooks/endpoints", `{"name":"bad","targetUrl":"https://169.254.169.254/latest/meta-data","eventTypes":["alert.created"],"signingSecret":"super-secret-webhook-value"}`, authHeaders)
	result.add("webhook SSRF target blocked", webhookSSRF.Code == http.StatusBadRequest && !strings.Contains(webhookSSRF.Body.String(), "super-secret"), "POST /api/v1/webhooks/endpoints metadata")
	webhookSafe := request(handler, http.MethodPost, "/api/v1/webhooks/endpoints", `{"name":"alerts","targetUrl":"https://hooks.example.com/events","eventTypes":["alert.created"],"signingSecret":"super-secret-webhook-value"}`, authHeaders)
	result.add("webhook signing secret not reflected", webhookSafe.Code == http.StatusOK && !strings.Contains(webhookSafe.Body.String(), "super-secret"), "POST /api/v1/webhooks/endpoints")

	metricMismatch := request(handler, http.MethodPost, "/api/v1/metrics/nodes/node-dast", `{"nodeId":"node-other","connections":1}`, authHeaders)
	result.add("metric node id mismatch blocked", metricMismatch.Code == http.StatusBadRequest, "POST /api/v1/metrics/nodes/{id}")

	wireGuardImport := request(handler, http.MethodPost, "/api/v1/warp/profiles/import-wireguard", `{"id":"warp-dast","name":"wg-dast","config":"[Interface]\nPrivateKey = EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=\nAddress = 172.16.0.4/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = engage.cloudflareclient.com:2408\n"}`, authHeaders)
	result.add("wireguard private key not reflected", wireGuardImport.Code == http.StatusOK && !strings.Contains(wireGuardImport.Body.String(), "EEEEEEEE"), "POST /api/v1/warp/profiles/import-wireguard")

	write(result)
	if !result.Passed {
		os.Exit(1)
	}
}

func (r *report) add(name string, passed bool, detail string) {
	r.Checks = append(r.Checks, check{Name: name, Passed: passed, Detail: detail})
	r.Passed = r.Passed && passed
}

func request(handler http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func hasSecurityHeaders(res *httptest.ResponseRecorder) bool {
	headers := res.Result().Header
	return headers.Get("Content-Security-Policy") != "" &&
		headers.Get("X-Content-Type-Options") == "nosniff" &&
		headers.Get("X-Frame-Options") == "DENY" &&
		headers.Get("Referrer-Policy") == "no-referrer"
}

func write(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		panic(err)
	}
}

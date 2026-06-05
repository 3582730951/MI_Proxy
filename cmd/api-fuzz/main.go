package main

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"sing-box-next-panel/services/controlplane"
)

type report struct {
	Cases       int      `json:"cases"`
	Server5xx   int      `json:"server5xx"`
	AuthBypass  int      `json:"authBypass"`
	CrashInputs []string `json:"crashInputs"`
	Passed      bool     `json:"passed"`
	Mode        string   `json:"mode"`
}

func main() {
	rng := rand.New(rand.NewSource(20260603))
	cp := controlplane.New(nil)
	handler := controlplane.NewHTTPHandler(cp)
	result := report{Cases: 1000, Passed: true, Mode: "local-api-fuzz-smoke"}

	paths := []string{
		"/api/v1/rules/test-domain?input=",
		"/api/v1/rules/rule-sets",
		"/api/v1/nodes/register",
		"/api/v1/nodes/kernel-tuning",
		"/api/v1/metrics/nodes/",
		"/api/v1/warp/profiles/import-wireguard",
		"/api/v1/argo/cloudflare/automation-plan",
		"/api/v1/webhooks/endpoints",
		"/api/v1/protocols/stats",
		"/api/v1/alerts/",
		"/api/v1/security/waivers",
		"/api/v1/subscriptions/conversions",
		"/sub/",
		"/api/v1/logs?file=",
		"/api/v1/incidents/runbooks",
		"/api/v1/incidents/",
	}
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}
	for i := 0; i < result.Cases; i++ {
		path := paths[rng.Intn(len(paths))] + fuzzURLString(rng, 64)
		if strings.HasPrefix(path, "/sub/") {
			path = "/sub/" + fuzzURLString(rng, 20) + "/" + fuzzURLString(rng, 12)
		}
		req := httptest.NewRequest(methods[rng.Intn(len(methods))], path, strings.NewReader(fuzzString(rng, 128)))
		if rng.Intn(3) == 0 {
			req.Header.Set("X-User-ID", "fuzz")
			req.Header.Set("X-Tenant-ID", "tenant-a")
			req.Header.Set("X-Role", string(controlplane.RoleOperator))
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code >= 500 {
			result.Server5xx++
			result.CrashInputs = append(result.CrashInputs, path)
		}
		if strings.HasPrefix(path, "/api/v1/nodes/register") && req.Header.Get("X-User-ID") == "" && res.Code >= 200 && res.Code < 300 {
			result.AuthBypass++
		}
	}
	result.Passed = result.Server5xx == 0 && result.AuthBypass == 0
	write(result)
	if !result.Passed {
		os.Exit(1)
	}
}

func fuzzString(rng *rand.Rand, maxLen int) string {
	alphabet := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/%?&=<>'\"{}[]:;\\\x00")
	n := rng.Intn(maxLen + 1)
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(out)
}

func fuzzURLString(rng *rand.Rand, maxLen int) string {
	alphabet := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/?&=")
	n := rng.Intn(maxLen + 1)
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(out)
}

func write(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		panic(err)
	}
}

var _ = time.Second

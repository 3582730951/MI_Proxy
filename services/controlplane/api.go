package controlplane

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"sing-box-next-panel/packages/rulecompiler"
)

func NewHTTPHandler(cp *ControlPlane) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, map[string]string{"status": "ok"}, nil)
	})
	mux.HandleFunc("/api/v1/nodes/register", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		if err := cp.CheckRateLimit(RateLimitAgentRegister, clientIP(r)); err != nil {
			writeJSON(w, nil, err)
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var reg NodeRegistration
		if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		node, err := cp.RegisterNode(ctx, reg)
		writeJSON(w, node, err)
	})
	mux.HandleFunc("/api/v1/nodes/kernel-tuning", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		rows, err := cp.KernelTuning(ctx, ctx.User.TenantID)
		writeJSON(w, rows, err)
	})
	mux.HandleFunc("/api/v1/auth/passkeys/register-options", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			RPID      string    `json:"rpId"`
			Origin    string    `json:"origin"`
			ExpiresAt time.Time `json:"expiresAt"`
		}
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		challenge, rawChallenge, err := cp.BeginPasskeyRegistration(ctx, req.RPID, req.Origin, req.ExpiresAt)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		writeJSON(w, passkeyChallengeResponse(challenge, rawChallenge), nil)
	})
	mux.HandleFunc("/api/v1/auth/passkeys/register", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			ChallengeID  string `json:"challengeId"`
			Challenge    string `json:"challenge"`
			CredentialID string `json:"credentialId"`
			PublicKey    string `json:"publicKey"`
			SignCount    uint32 `json:"signCount"`
		}
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		credential, err := cp.RegisterPasskey(ctx, req.ChallengeID, req.Challenge, req.CredentialID, req.PublicKey, req.SignCount)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		credential.PublicKey = ""
		writeJSON(w, credential, nil)
	})
	mux.HandleFunc("/api/v1/auth/passkeys/authentication-options", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		if err := cp.CheckRateLimit(RateLimitLogin, clientIP(r)); err != nil {
			writeJSON(w, nil, err)
			return
		}
		var req struct {
			UserID       string    `json:"userId"`
			CredentialID string    `json:"credentialId"`
			RPID         string    `json:"rpId"`
			Origin       string    `json:"origin"`
			ExpiresAt    time.Time `json:"expiresAt"`
		}
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		challenge, rawChallenge, err := cp.BeginPasskeyAuthentication(req.UserID, req.CredentialID, req.RPID, req.Origin, req.ExpiresAt)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		writeJSON(w, passkeyChallengeResponse(challenge, rawChallenge), nil)
	})
	mux.HandleFunc("/api/v1/auth/passkeys/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		if err := cp.CheckRateLimit(RateLimitLogin, clientIP(r)); err != nil {
			writeJSON(w, nil, err)
			return
		}
		var req struct {
			ChallengeID string `json:"challengeId"`
			Challenge   string `json:"challenge"`
			Signature   string `json:"signature"`
			SignCount   uint32 `json:"signCount"`
		}
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		signature, err := base64.RawURLEncoding.DecodeString(req.Signature)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ctx, err := cp.VerifyPasskeyAuthentication(req.ChallengeID, req.Challenge, signature, req.SignCount, clientIP(r))
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		writeJSON(w, map[string]any{
			"authenticated":     true,
			"userId":            ctx.User.ID,
			"tenantId":          ctx.User.TenantID,
			"role":              ctx.User.Role,
			"csrfToken":         CsrfToken(ctx.User.ID),
			"confirmationToken": ConfirmationToken(ctx.User.ID),
		}, nil)
	})
	mux.HandleFunc("/api/v1/nodes", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/nodes" {
			http.NotFound(w, r)
			return
		}
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		nodes, err := cp.ListNodes(ctx, ctx.User.TenantID)
		writeJSON(w, nodes, err)
	})
	mux.HandleFunc("/api/v1/nodes/", func(w http.ResponseWriter, r *http.Request) {
		parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"))
		if len(parts) == 1 && r.Method == http.MethodGet {
			ctx, err := cp.requestContext(r)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			node, err := cp.GetNode(ctx, parts[0])
			writeJSON(w, node, err)
			return
		}
		if len(parts) == 2 && parts[1] == "heartbeat" && r.Method == http.MethodPost {
			ctx, err := cp.heartbeatRequestContext(r, parts[0])
			if err != nil {
				writeJSON(w, nil, err)
				return
			}
			var hb Heartbeat
			if err := decodeJSON(r, &hb); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]bool{"ok": true}, cp.Heartbeat(ctx, parts[0], hb))
			return
		}
		if len(parts) == 2 && parts[1] == "deploy-config" && r.Method == http.MethodPost {
			if err := cp.CheckRateLimit(RateLimitConfigDeploy, clientIP(r)+":"+parts[0]); err != nil {
				writeJSON(w, nil, err)
				return
			}
			ctx, err := cp.requestContext(r)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var req struct {
				Content         string `json:"content"`
				SimulateFailure bool   `json:"simulateFailure"`
			}
			if err := decodeJSON(r, &req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			deployment, err := cp.DeployConfig(ctx, parts[0], req.Content, req.SimulateFailure)
			writeJSON(w, deployment, err)
			return
		}
		if len(parts) == 2 && parts[1] == "rollback" && r.Method == http.MethodPost {
			ctx, err := cp.requestContext(r)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var req struct {
				Version int `json:"version"`
			}
			if err := decodeJSON(r, &req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			cfg, err := cp.RollbackConfig(ctx, ctx.User.TenantID, req.Version)
			writeJSON(w, cfg, err)
			return
		}
		if len(parts) == 2 && parts[1] == "agent-credential" && r.Method == http.MethodPost {
			ctx, err := cp.requestContext(r)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var req struct {
				ExpiresAt time.Time `json:"expiresAt"`
			}
			if r.Body != nil && r.ContentLength != 0 {
				if err := decodeJSON(r, &req); err != nil {
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
			}
			credential, fingerprint, err := cp.RotateAgentCredential(ctx, parts[0], req.ExpiresAt)
			if err != nil {
				writeJSON(w, nil, err)
				return
			}
			writeJSON(w, map[string]any{
				"id":          credential.ID,
				"nodeId":      credential.NodeID,
				"tenantId":    credential.TenantID,
				"expiresAt":   credential.ExpiresAt,
				"fingerprint": fingerprint,
			}, nil)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/rules" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if err := authorize(ctx.User, "rules:read", ctx.User.TenantID); err != nil {
				writeJSON(w, nil, err)
				return
			}
			cp.mu.RLock()
			rules := cp.rulePolicy.Rules()
			cp.mu.RUnlock()
			writeJSON(w, rules, nil)
		case http.MethodPost:
			var rule rulecompiler.Rule
			if err := decodeJSON(r, &rule); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			report, err := cp.PublishRules(ctx, ctx.User.TenantID, rulecompiler.CompileOptions{Rules: []rulecompiler.Rule{rule}})
			writeJSON(w, report, err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/rules/compile", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var opts rulecompiler.CompileOptions
		if err := decodeJSON(r, &opts); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		policy, err := rulecompiler.Compile(opts)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		if err := authorize(ctx.User, "rules:read", ctx.User.TenantID); err != nil {
			writeJSON(w, nil, err)
			return
		}
		writeJSON(w, map[string]any{"rules": policy.Rules(), "count": len(policy.Rules())}, nil)
	})
	mux.HandleFunc("/api/v1/rules/test-domain", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := authorize(ctx.User, "rules:read", ctx.User.TenantID); err != nil {
			writeJSON(w, nil, err)
			return
		}
		var input string
		switch r.Method {
		case http.MethodGet:
			input = r.URL.Query().Get("input")
		case http.MethodPost:
			var req struct {
				Input string `json:"input"`
			}
			if err := decodeJSON(r, &req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			input = req.Input
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, cp.TestDomain(input), nil)
	})
	mux.HandleFunc("/api/v1/rules/publish", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var opts rulecompiler.CompileOptions
		if err := decodeJSON(r, &opts); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		report, err := cp.PublishRules(ctx, ctx.User.TenantID, opts)
		writeJSON(w, report, err)
	})
	mux.HandleFunc("/api/v1/rules/rollback", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		cp.auditLockedSafe(ctx, ctx.User.TenantID, "rules.rollback", "rules", "active")
		writeJSON(w, map[string]bool{"ok": true}, nil)
	})
	mux.HandleFunc("/api/v1/rules/rule-sets", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/rules/rule-sets" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			sources, err := cp.ListRuleSetSources(ctx, ctx.User.TenantID)
			writeJSON(w, sources, err)
		case http.MethodPost:
			var source RuleSetSource
			if err := decodeJSON(r, &source); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			source.TenantID = nonEmpty(source.TenantID, ctx.User.TenantID)
			created, err := cp.RegisterRuleSetSource(ctx, source)
			writeJSON(w, created, err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/webhooks/endpoints", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/webhooks/endpoints" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			endpoints, err := cp.ListWebhookEndpoints(ctx, ctx.User.TenantID)
			writeJSON(w, endpoints, err)
		case http.MethodPost:
			var req WebhookEndpointRegistration
			if err := decodeJSON(r, &req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			req.TenantID = nonEmpty(req.TenantID, ctx.User.TenantID)
			endpoint, err := cp.RegisterWebhookEndpoint(ctx, req)
			writeJSON(w, endpoint, err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/routes/trace", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req RouteTraceRequest
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		trace, err := cp.TraceRouteDecision(ctx, ctx.User.TenantID, req)
		writeJSON(w, trace, err)
	})
	mux.HandleFunc("/api/v1/routes/traces", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		traces, err := cp.RouteDecisionTraces(ctx, ctx.User.TenantID, limit)
		writeJSON(w, traces, err)
	})
	mux.HandleFunc("/api/v1/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/subscriptions" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			subs, err := cp.ListSubscriptions(ctx, ctx.User.TenantID)
			writeJSON(w, subs, err)
		case http.MethodPost:
			var req struct {
				UserID           string   `json:"userId"`
				ClientType       string   `json:"clientType"`
				PolicyID         string   `json:"policyId"`
				DeviceID         string   `json:"deviceId"`
				Region           string   `json:"region"`
				Protocol         string   `json:"protocol"`
				OutboundPolicy   string   `json:"outboundPolicy"`
				ExpiresInSeconds int64    `json:"expiresInSeconds"`
				TokenKind        string   `json:"tokenKind"`
				Scope            string   `json:"scope"`
				IPAllowlist      []string `json:"ipAllowlist"`
				UsesRemaining    int      `json:"usesRemaining"`
			}
			if err := decodeJSON(r, &req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			expiresAt := time.Time{}
			if req.ExpiresInSeconds > 0 {
				expiresAt = cp.now().Add(time.Duration(req.ExpiresInSeconds) * time.Second)
			}
			sub, token, err := cp.CreateSubscriptionWithOptions(ctx, ctx.User.TenantID, req.UserID, nonEmpty(req.ClientType, "sing-box"), req.PolicyID, expiresAt, SubscriptionOptions{
				TokenKind:      req.TokenKind,
				Scope:          req.Scope,
				IPAllowlist:    req.IPAllowlist,
				UsesRemaining:  req.UsesRemaining,
				DeviceID:       req.DeviceID,
				Region:         req.Region,
				Protocol:       req.Protocol,
				OutboundPolicy: req.OutboundPolicy,
			})
			writeJSON(w, map[string]any{
				"subscription": map[string]any{
					"id":             sub.ID,
					"tenantId":       sub.TenantID,
					"userId":         sub.UserID,
					"clientType":     sub.ClientType,
					"policyId":       sub.PolicyID,
					"deviceId":       sub.DeviceID,
					"region":         sub.Region,
					"protocol":       sub.Protocol,
					"outboundPolicy": sub.OutboundPolicy,
					"tokenKind":      sub.TokenKind,
					"scope":          sub.Scope,
					"expiresAt":      sub.ExpiresAt,
				},
				"token": token,
			}, err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/subscriptions/conversions", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/subscriptions/conversions" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			conversions, err := cp.ListSubscriptionConversions(ctx, ctx.User.TenantID)
			writeJSON(w, conversions, err)
		case http.MethodPost:
			var req SubscriptionConversionRequest
			if err := decodeJSON(r, &req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			req.TenantID = nonEmpty(req.TenantID, ctx.User.TenantID)
			conversion, err := cp.RegisterSubscriptionConversion(ctx, req)
			writeJSON(w, conversion, err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/subscriptions/", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/v1/subscriptions/"))
		if len(parts) == 2 && parts[1] == "revoke" && r.Method == http.MethodPost {
			writeJSON(w, map[string]bool{"ok": true}, cp.RevokeSubscription(ctx, parts[0]))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/api/v1/warp/profiles", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/warp/profiles" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			profiles, err := cp.ListWarpProfiles(ctx, ctx.User.TenantID)
			writeJSON(w, profiles, err)
		case http.MethodPost:
			var profile WarpProfile
			if err := decodeJSON(r, &profile); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			profile.TenantID = nonEmpty(profile.TenantID, ctx.User.TenantID)
			created, err := cp.AddWarpProfile(ctx, profile)
			writeJSON(w, redactWarpProfile(created), err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/warp/profiles/", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/v1/warp/profiles/"))
		if len(parts) == 1 && parts[0] == "import-wireguard" && r.Method == http.MethodPost {
			var req WarpWireGuardImport
			if err := decodeJSON(r, &req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			req.TenantID = nonEmpty(req.TenantID, ctx.User.TenantID)
			profile, err := cp.ImportWarpWireGuardProfile(ctx, req)
			writeJSON(w, redactWarpProfile(profile), err)
			return
		}
		if len(parts) == 2 && parts[1] == "probe" && r.Method == http.MethodPost {
			var probe WarpProbeResult
			if err := decodeJSON(r, &probe); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]bool{"ok": true}, cp.ProbeWarpProfile(parts[0], probe))
			return
		}
		if len(parts) == 2 && parts[1] == "disable" && r.Method == http.MethodPost {
			writeJSON(w, map[string]bool{"ok": true}, cp.DisableWarpProfile(ctx, parts[0]))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/api/v1/argo/tunnels", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/argo/tunnels" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			tunnels, err := cp.ListArgoTunnels(ctx, ctx.User.TenantID)
			writeJSON(w, tunnels, err)
		case http.MethodPost:
			var tunnel ArgoTunnel
			if err := decodeJSON(r, &tunnel); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			tunnel.TenantID = nonEmpty(tunnel.TenantID, ctx.User.TenantID)
			created, err := cp.RegisterArgoTunnel(ctx, tunnel)
			writeJSON(w, created, err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/argo/cloudflare/automation-plan", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		var req CloudflareArgoAutomationRequest
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req.TenantID = nonEmpty(req.TenantID, ctx.User.TenantID)
		plan, err := cp.BuildCloudflareArgoAutomationPlan(ctx, req)
		writeJSON(w, plan, err)
	})
	mux.HandleFunc("/api/v1/argo/tunnels/", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/v1/argo/tunnels/"))
		if len(parts) == 2 && parts[1] == "config" && r.Method == http.MethodGet {
			config, err := cp.RenderArgoTunnelConfig(ctx, parts[0])
			if err != nil {
				writeJSON(w, nil, err)
				return
			}
			w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(config))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/api/v1/protocols/stats", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		stats, err := cp.ProtocolStats(ctx, ctx.User.TenantID)
		writeJSON(w, stats, err)
	})
	mux.HandleFunc("/api/v1/metrics/nodes/", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/v1/metrics/nodes/"))
		if len(parts) != 1 {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			samples, err := cp.QueryNodeMetrics(ctx, ctx.User.TenantID, parts[0], limit)
			writeJSON(w, samples, err)
		case http.MethodPost:
			var sample NodeMetricSample
			if err := decodeJSON(r, &sample); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if sample.NodeID != "" && sample.NodeID != parts[0] {
				writeJSON(w, nil, ErrBadRequest)
				return
			}
			sample.NodeID = parts[0]
			sample, err := cp.RecordNodeMetric(ctx, sample)
			writeJSON(w, sample, err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/metrics/overview", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		metrics, err := cp.Overview(ctx, ctx.User.TenantID)
		writeJSON(w, metrics, err)
	})
	mux.HandleFunc("/api/v1/metrics/capacity", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		capacity, err := cp.CapacityPlan(ctx, ctx.User.TenantID)
		writeJSON(w, capacity, err)
	})
	mux.HandleFunc("/api/v1/metrics/dependencies", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		availability, err := cp.CoreAPIAvailability(ctx, ctx.User.TenantID)
		writeJSON(w, availability, err)
	})
	mux.HandleFunc("/api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		lines, err := cp.Logs(ctx, ctx.User.TenantID)
		writeJSON(w, lines, err)
	})
	mux.HandleFunc("/api/v1/audit-logs", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		logs, err := cp.AuditLogs(ctx, ctx.User.TenantID)
		writeJSON(w, logs, err)
	})
	mux.HandleFunc("/api/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		alerts, err := cp.Alerts(ctx, ctx.User.TenantID)
		writeJSON(w, alerts, err)
	})
	mux.HandleFunc("/api/v1/alerts/", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/"))
		if len(parts) == 2 && parts[1] == "ack" && r.Method == http.MethodPost {
			alert, err := cp.AcknowledgeAlert(ctx, ctx.User.TenantID, parts[0])
			writeJSON(w, alert, err)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/api/v1/security/waivers", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			waivers, err := cp.ListSecurityWaivers(ctx, ctx.User.TenantID)
			writeJSON(w, waivers, err)
		case http.MethodPost:
			var waiver SecurityWaiver
			if err := decodeJSON(r, &waiver); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			waiver.TenantID = nonEmpty(waiver.TenantID, ctx.User.TenantID)
			created, err := cp.CreateSecurityWaiver(ctx, waiver)
			writeJSON(w, created, err)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/incidents", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		incidents, err := cp.Incidents(ctx, ctx.User.TenantID)
		writeJSON(w, incidents, err)
	})
	mux.HandleFunc("/api/v1/incidents/runbooks", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		catalog, err := cp.RunbookCatalog(ctx, ctx.User.TenantID)
		writeJSON(w, catalog, err)
	})
	mux.HandleFunc("/api/v1/incidents/", func(w http.ResponseWriter, r *http.Request) {
		ctx, err := cp.requestContext(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		parts := pathParts(strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/"))
		if len(parts) == 3 && parts[1] == "runbook" && r.Method == http.MethodPost {
			writeJSON(w, map[string]bool{"ok": true}, cp.Runbook(ctx, ctx.User.TenantID, parts[0], parts[2]))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/sub/"), "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		content, err := cp.RenderSubscription(parts[0], parts[1], clientIP(r))
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		etag := `"` + shortHash(content) + `"`
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Vary", "Accept-Encoding")
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		body, encoding, err := encodeSubscriptionContent(content, r.Header.Get("Accept-Encoding"))
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		if encoding != "" {
			w.Header().Set("Content-Encoding", encoding)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	return securityMiddleware(cp, mux)
}

func securityMiddleware(cp *ControlPlane, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if origin := r.Header.Get("Origin"); origin != "" {
			if _, ok := cp.allowedOrigins[origin]; !ok {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-ABAC-Environments, X-ABAC-Node-Tags, X-ABAC-Regions, X-Agent-Cert-SHA256, X-Agent-Node-ID, X-Confirm-Token, X-CSRF-Token, X-Role, X-Tenant-ID, X-User-ID")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if isStateChanging(r) && !isLoginPath(r.URL.Path) && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				userID := r.Header.Get("X-User-ID")
				if userID == "" || r.Header.Get("X-CSRF-Token") != CsrfToken(userID) {
					http.Error(w, "csrf token required", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func TLS13Config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{
			"h2",
			"http/1.1",
		},
	}
}

func (cp *ControlPlane) auditLockedSafe(ctx RequestContext, tenantID, action, resourceType, resourceID string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.auditLocked(ctx, tenantID, action, resourceType, resourceID)
}

func requestContext(r *http.Request) (RequestContext, error) {
	userID := r.Header.Get("X-User-ID")
	tenantID := r.Header.Get("X-Tenant-ID")
	role := Role(r.Header.Get("X-Role"))
	if userID == "" || tenantID == "" || role == "" {
		return RequestContext{}, ErrUnauthorized
	}
	ctx := RequestContext{
		User:      User{ID: userID, TenantID: tenantID, Role: role},
		IP:        net.ParseIP(clientIP(r)),
		Confirmed: r.Header.Get("X-Confirm-Token") == ConfirmationToken(userID),
	}
	applyABACHeaders(&ctx, r)
	return ctx, nil
}

func (cp *ControlPlane) requestContext(r *http.Request) (RequestContext, error) {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		ctx, err := cp.AuthenticateAPIToken(strings.TrimPrefix(auth, "Bearer "), clientIP(r))
		if err != nil {
			return RequestContext{}, err
		}
		if r.Header.Get("X-Confirm-Token") == ConfirmationToken(ctx.User.ID) {
			ctx.Confirmed = true
		}
		applyABACHeaders(&ctx, r)
		return ctx, nil
	}
	return requestContext(r)
}

func (cp *ControlPlane) heartbeatRequestContext(r *http.Request, nodeID string) (RequestContext, error) {
	if r.Header.Get("X-Agent-Node-ID") != "" || r.Header.Get("X-Agent-Cert-SHA256") != "" {
		if r.Header.Get("X-Agent-Node-ID") != nodeID {
			return RequestContext{}, ErrForbidden
		}
		return cp.AuthenticateAgent(nodeID, r.Header.Get("X-Agent-Cert-SHA256"), clientIP(r))
	}
	return cp.requestContext(r)
}

func applyABACHeaders(ctx *RequestContext, r *http.Request) {
	ctx.AllowedRegions = splitCSVHeader(r.Header.Get("X-ABAC-Regions"))
	ctx.AllowedNodeTags = splitCSVHeader(r.Header.Get("X-ABAC-Node-Tags"))
	ctx.AllowedEnvironments = splitCSVHeader(r.Header.Get("X-ABAC-Environments"))
}

func splitCSVHeader(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, value any, err error) {
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrUnauthorized):
			status = http.StatusUnauthorized
		case errors.Is(err, ErrBadRequest):
			status = http.StatusBadRequest
		case errors.Is(err, ErrForbidden):
			status = http.StatusForbidden
		case errors.Is(err, ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, ErrRevoked):
			status = http.StatusGone
		case errors.Is(err, ErrRateLimited):
			status = http.StatusTooManyRequests
		case errors.Is(err, ErrReleasePaused):
			status = http.StatusServiceUnavailable
		case errors.Is(err, ErrConfirmationRequired):
			status = http.StatusPreconditionRequired
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(value)
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func decodeJSON(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

func encodeSubscriptionContent(content, acceptEncoding string) ([]byte, string, error) {
	if acceptsEncoding(acceptEncoding, "br") {
		var buf bytes.Buffer
		writer := brotli.NewWriter(&buf)
		if _, err := writer.Write([]byte(content)); err != nil {
			return nil, "", err
		}
		if err := writer.Close(); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "br", nil
	}
	if acceptsEncoding(acceptEncoding, "gzip") {
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		if _, err := writer.Write([]byte(content)); err != nil {
			return nil, "", err
		}
		if err := writer.Close(); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "gzip", nil
	}
	return []byte(content), "", nil
}

func acceptsEncoding(header, encoding string) bool {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	for _, item := range strings.Split(header, ",") {
		parts := strings.Split(item, ";")
		if len(parts) == 0 || strings.ToLower(strings.TrimSpace(parts[0])) != encoding {
			continue
		}
		q := 1.0
		for _, part := range parts[1:] {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok || strings.ToLower(strings.TrimSpace(key)) != "q" {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err == nil {
				q = parsed
			}
		}
		return q > 0
	}
	return false
}

func pathParts(path string) []string {
	raw := strings.Split(strings.Trim(path, "/"), "/")
	parts := make([]string, 0, len(raw))
	for _, part := range raw {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func passkeyChallengeResponse(challenge PasskeyChallenge, rawChallenge string) map[string]any {
	return map[string]any{
		"challengeId":  challenge.ID,
		"challenge":    rawChallenge,
		"kind":         challenge.Kind,
		"userId":       challenge.UserID,
		"credentialId": challenge.CredentialID,
		"rpId":         challenge.RPID,
		"origin":       challenge.Origin,
		"expiresAt":    challenge.ExpiresAt,
	}
}

func isStateChanging(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
}

func isLoginPath(path string) bool {
	return path == "/api/v1/auth/passkeys/authentication-options" || path == "/api/v1/auth/passkeys/authenticate"
}

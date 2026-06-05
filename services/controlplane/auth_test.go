package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOIDCConfigValidationAndTOTP(t *testing.T) {
	if err := ValidateOIDCConfig(OIDCConfig{Enabled: true, IssuerURL: "http://issuer.example", ClientID: "client", RedirectURL: "https://panel.example/callback"}); err == nil {
		t.Fatal("OIDC issuer must require https")
	}
	if err := ValidateOIDCConfig(OIDCConfig{Enabled: true, IssuerURL: "https://issuer.example", ClientID: "client", RedirectURL: "https://panel.example/callback"}); err != nil {
		t.Fatalf("valid OIDC config rejected: %v", err)
	}

	secret := "JBSWY3DPEHPK3PXP"
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	code := TOTPForTest(secret, now)
	if code == "" || !VerifyTOTP(secret, code, now) {
		t.Fatalf("valid TOTP code rejected: %q", code)
	}
	if VerifyTOTP(secret, "000000", now) {
		t.Fatal("invalid TOTP code accepted")
	}
}

func TestOIDCJWTHeaderRejectsAlgNoneAndUnsafeKid(t *testing.T) {
	header, err := ValidateOIDCJWTHeader(testJWT(`{"alg":"RS256","kid":"tenant-key-1","typ":"JWT"}`), []string{"RS256"})
	if err != nil {
		t.Fatalf("valid JWT header rejected: %v", err)
	}
	if header.Algorithm != "RS256" || header.KeyID != "tenant-key-1" {
		t.Fatalf("unexpected JWT header: %+v", header)
	}
	for name, token := range map[string]string{
		"alg none":        testJWT(`{"alg":"none","kid":"tenant-key-1"}`),
		"disallowed alg":  testJWT(`{"alg":"HS256","kid":"tenant-key-1"}`),
		"path traversal":  testJWT(`{"alg":"RS256","kid":"../../private.pem"}`),
		"url kid":         testJWT(`{"alg":"RS256","kid":"https://issuer.example/jwks.json"}`),
		"whitespace kid":  testJWT(`{"alg":"RS256","kid":"tenant key 1"}`),
		"missing segment": "only.two",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateOIDCJWTHeader(token, []string{"RS256"}); err == nil {
				t.Fatal("unsafe JWT header accepted")
			}
		})
	}
}

func TestSessionCookieRotatesAndUsesSecureFlags(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	first, err := NewSessionCookie("__Host-mi-session", expiresAt)
	if err != nil {
		t.Fatalf("new session cookie: %v", err)
	}
	second, err := NewSessionCookie("__Host-mi-session", expiresAt)
	if err != nil {
		t.Fatalf("second session cookie: %v", err)
	}
	if first.Value == "" || first.Value == second.Value {
		t.Fatalf("session cookie was not rotated: first=%q second=%q", first.Value, second.Value)
	}
	if !first.Secure || !first.HttpOnly || first.SameSite != http.SameSiteStrictMode || first.Path != "/" || first.Domain != "" || first.MaxAge <= 0 {
		t.Fatalf("session cookie missing secure flags: %+v", first)
	}
	cookieHeader := first.String()
	for _, want := range []string{"Secure", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(cookieHeader, want) {
			t.Fatalf("cookie header %q missing %s", cookieHeader, want)
		}
	}
	if _, err := NewSessionCookie("", expiresAt); err == nil {
		t.Fatal("empty session cookie name accepted")
	}
}

func TestPasskeyOriginPublicKeyAndSignatureValidation(t *testing.T) {
	if err := ValidatePasskeyRPOrigin("example.com", "https://panel.example.com"); err != nil {
		t.Fatalf("valid passkey origin rejected: %v", err)
	}
	if err := ValidatePasskeyRPOrigin("example.com", "https://evil.test"); err == nil {
		t.Fatal("cross-RP passkey origin accepted")
	}
	if err := ValidatePasskeyRPOrigin("example.com", "http://panel.example.com"); err == nil {
		t.Fatal("insecure passkey origin accepted")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate passkey key: %v", err)
	}
	encoded, err := EncodePasskeyPublicKey(privateKey.PublicKey)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	hash := PasskeySignatureHash("challenge", "example.com", "https://panel.example.com", "admin", "cred-1", 2)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	if !VerifyPasskeyAssertion(encoded, "challenge", "example.com", "https://panel.example.com", "admin", "cred-1", 2, signature) {
		t.Fatal("valid passkey assertion rejected")
	}
	if VerifyPasskeyAssertion(encoded, "challenge", "example.com", "https://panel.example.com", "admin", "cred-1", 3, signature) {
		t.Fatal("passkey assertion accepted with tampered sign count")
	}
}

func TestCORSAndCSRFProtection(t *testing.T) {
	cp := New(nil)
	server := NewHTTPHandler(cp)
	headers := map[string]string{"X-User-ID": "admin", "X-Tenant-ID": "tenant-a", "X-Role": string(RoleAdmin), "X-Confirm-Token": ConfirmationToken("admin")}

	blocked := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/register", strings.NewReader(`{"id":"node-1","tenantId":"tenant-a"}`))
	blocked.Header.Set("Origin", "https://evil.example")
	for key, value := range headers {
		blocked.Header.Set(key, value)
	}
	blockedRes := httptest.NewRecorder()
	server.ServeHTTP(blockedRes, blocked)
	if blockedRes.Code != http.StatusForbidden {
		t.Fatalf("bad origin status=%d want 403", blockedRes.Code)
	}

	missingCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/register", strings.NewReader(`{"id":"node-1","tenantId":"tenant-a"}`))
	missingCSRF.Header.Set("Origin", "http://127.0.0.1:8080")
	for key, value := range headers {
		missingCSRF.Header.Set(key, value)
	}
	missingRes := httptest.NewRecorder()
	server.ServeHTTP(missingRes, missingCSRF)
	if missingRes.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status=%d want 403", missingRes.Code)
	}

	allowed := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/register", strings.NewReader(`{"id":"node-1","tenantId":"tenant-a"}`))
	allowed.Header.Set("Origin", "http://127.0.0.1:8080")
	allowed.Header.Set("X-CSRF-Token", CsrfToken("admin"))
	for key, value := range headers {
		allowed.Header.Set(key, value)
	}
	allowedRes := httptest.NewRecorder()
	server.ServeHTTP(allowedRes, allowed)
	if allowedRes.Code != http.StatusOK {
		t.Fatalf("valid csrf status=%d body=%s", allowedRes.Code, allowedRes.Body.String())
	}
	if allowedRes.Header().Get("Access-Control-Allow-Origin") != "http://127.0.0.1:8080" {
		t.Fatal("allowed CORS origin not reflected")
	}
}

func TestTLS13GatewayConfig(t *testing.T) {
	cfg := TLS13Config()
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLS min version=%x want TLS 1.3", cfg.MinVersion)
	}
	if len(cfg.NextProtos) == 0 || cfg.NextProtos[0] != "h2" {
		t.Fatalf("TLS config should prefer HTTP/2: %+v", cfg.NextProtos)
	}
}

func testJWT(header string) string {
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(header))
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`))
	return encodedHeader + "." + encodedPayload + ".signature"
}

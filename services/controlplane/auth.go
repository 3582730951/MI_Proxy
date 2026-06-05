package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Enabled      bool
}

type JWTHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

const passwordHashIterations = 120_000
const passwordHashKeyLen = 32
const passwordHashSaltLen = 16

var errPasswordHashFormat = errors.New("invalid password hash format")

func ValidateOIDCConfig(cfg OIDCConfig) error {
	if !cfg.Enabled {
		return nil
	}
	for name, value := range map[string]string{
		"issuerURL":   cfg.IssuerURL,
		"clientID":    cfg.ClientID,
		"redirectURL": cfg.RedirectURL,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("missing %s", name)
		}
	}
	issuer, err := url.Parse(cfg.IssuerURL)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		return errors.New("issuerURL must be an https URL")
	}
	redirect, err := url.Parse(cfg.RedirectURL)
	if err != nil || redirect.Scheme != "https" || redirect.Host == "" {
		return errors.New("redirectURL must be an https URL")
	}
	return nil
}

func ValidateOIDCJWTHeader(token string, allowedAlgorithms []string) (JWTHeader, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return JWTHeader{}, errors.New("jwt must have three non-empty segments")
	}
	rawHeader, err := decodeBase64URLSegment(parts[0])
	if err != nil {
		return JWTHeader{}, errors.New("jwt header is not valid base64url")
	}
	var header JWTHeader
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return JWTHeader{}, errors.New("jwt header is not valid json")
	}
	header.Algorithm = strings.TrimSpace(header.Algorithm)
	header.KeyID = strings.TrimSpace(header.KeyID)
	header.Type = strings.TrimSpace(header.Type)
	if !jwtAlgorithmAllowed(header.Algorithm, allowedAlgorithms) {
		return JWTHeader{}, errors.New("jwt alg is not allowed")
	}
	if err := validateJWTKeyID(header.KeyID); err != nil {
		return JWTHeader{}, err
	}
	return header, nil
}

func decodeBase64URLSegment(segment string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(segment); err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.DecodeString(segment)
}

func jwtAlgorithmAllowed(algorithm string, allowedAlgorithms []string) bool {
	algorithm = strings.TrimSpace(algorithm)
	if algorithm == "" || strings.EqualFold(algorithm, "none") {
		return false
	}
	if len(allowedAlgorithms) == 0 {
		allowedAlgorithms = []string{"RS256", "ES256"}
	}
	for _, allowed := range allowedAlgorithms {
		if algorithm == strings.TrimSpace(allowed) {
			return true
		}
	}
	return false
}

func validateJWTKeyID(keyID string) error {
	if keyID == "" {
		return nil
	}
	if len(keyID) > 128 {
		return errors.New("jwt kid is too long")
	}
	if strings.Contains(keyID, "..") {
		return errors.New("jwt kid contains traversal")
	}
	for i := 0; i < len(keyID); i++ {
		c := keyID[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return errors.New("jwt kid contains unsafe character")
	}
	return nil
}

func VerifyTOTP(secretBase32, code string, now time.Time) bool {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secretBase32)))
	if err != nil {
		return false
	}
	code = strings.TrimSpace(code)
	step := now.Unix() / 30
	for drift := int64(-1); drift <= 1; drift++ {
		if totpAt(secret, uint64(step+drift)) == code {
			return true
		}
	}
	return false
}

func TOTPForTest(secretBase32 string, now time.Time) string {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secretBase32)))
	if err != nil {
		return ""
	}
	return totpAt(secret, uint64(now.Unix()/30))
}

func CsrfToken(userID string) string {
	sum := sha256.Sum256([]byte("csrf-v1:" + userID))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func NewPasswordHash(password string) (string, error) {
	password = strings.TrimSpace(password)
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	salt := make([]byte, passwordHashSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return EncodePasswordHash(password, salt, passwordHashIterations)
}

func EncodePasswordHash(password string, salt []byte, iterations int) (string, error) {
	if iterations < 100_000 || len(salt) < passwordHashSaltLen {
		return "", errPasswordHashFormat
	}
	derived := pbkdf2SHA256([]byte(password), salt, iterations, passwordHashKeyLen)
	return strings.Join([]string{
		"pbkdf2-sha256",
		fmt.Sprintf("%d", iterations),
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(derived),
	}, "$"), nil
}

func VerifyPasswordHash(encodedHash, password string) bool {
	parts := strings.Split(strings.TrimSpace(encodedHash), "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 100_000 {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < passwordHashSaltLen {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(want) != passwordHashKeyLen {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iterations, len(want))
	return hmac.Equal(got, want)
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], uint32(block))
		_, _ = mac.Write(counter[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func NewSessionCookie(name string, expiresAt time.Time) (http.Cookie, error) {
	if strings.TrimSpace(name) == "" {
		return http.Cookie{}, errors.New("session cookie name is required")
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return http.Cookie{}, err
	}
	cookie := http.Cookie{
		Name:     name,
		Value:    base64.RawURLEncoding.EncodeToString(value),
		Path:     "/",
		Expires:  expiresAt,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if !expiresAt.IsZero() {
		cookie.MaxAge = int(time.Until(expiresAt).Seconds())
	}
	return cookie, nil
}

func ValidatePasskeyRPOrigin(rpID, origin string) error {
	rpID = strings.ToLower(strings.TrimSpace(rpID))
	if rpID == "" || strings.ContainsAny(rpID, `/\`) {
		return errors.New("rpID must be a DNS name")
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("passkey origin must be an https URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return errors.New("passkey origin is not under rpID")
	}
	return nil
}

func EncodePasskeyPublicKey(publicKey ecdsa.PublicKey) (string, error) {
	if publicKey.Curve != elliptic.P256() || publicKey.X == nil || publicKey.Y == nil || !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return "", errors.New("passkey public key must be P-256")
	}
	return base64.RawURLEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), publicKey.X, publicKey.Y)), nil
}

func DecodePasskeyPublicKey(encoded string) (ecdsa.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return ecdsa.PublicKey{}, err
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil || y == nil {
		return ecdsa.PublicKey{}, errors.New("invalid P-256 public key")
	}
	return ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func HashPasskeyChallenge(challenge string) string {
	sum := sha256.Sum256([]byte("passkey-challenge-v1:" + challenge))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func PasskeySignatureHash(challenge, rpID, origin, userID, credentialID string, signCount uint32) []byte {
	payload := strings.Join([]string{
		"passkey-assertion-v1",
		challenge,
		strings.ToLower(strings.TrimSpace(rpID)),
		strings.ToLower(strings.TrimSpace(origin)),
		userID,
		credentialID,
		fmt.Sprintf("%d", signCount),
	}, "\x00")
	sum := sha256.Sum256([]byte(payload))
	return sum[:]
}

func VerifyPasskeyAssertion(encodedPublicKey, challenge, rpID, origin, userID, credentialID string, signCount uint32, signature []byte) bool {
	publicKey, err := DecodePasskeyPublicKey(encodedPublicKey)
	if err != nil {
		return false
	}
	if err := ValidatePasskeyRPOrigin(rpID, origin); err != nil {
		return false
	}
	hash := PasskeySignatureHash(challenge, rpID, origin, userID, credentialID, signCount)
	if ecdsa.VerifyASN1(&publicKey, hash, signature) {
		return true
	}
	if len(signature) == 64 {
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		return ecdsa.Verify(&publicKey, hash, r, s)
	}
	return false
}

func totpAt(secret []byte, counter uint64) string {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(msg)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", value%1_000_000)
}

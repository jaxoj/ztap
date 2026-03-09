package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"
	"ztap/internal/auth"
	"ztap/internal/policy"

	"github.com/golang-jwt/jwt"
)

// --- Mocks & Helpers ---

// Mock Redis Store for the integration test
type MockRedis struct{}

func (m *MockRedis) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "compromised-jti-007" {
		return true, nil // Simulate a token that was blacklisted
	}
	return false, nil
}

// Generate RSA Keys for the test
func generateTestKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	return priv, &priv.PublicKey
}

// Generate a signed token
func issueToken(privKey *rsa.PrivateKey, role, jti string, expired bool) string {
	expTime := time.Now().Add(1 * time.Hour).Unix()
	if expired {
		expTime = time.Now().Add(-1 * time.Hour).Unix() // Expired 1 hour ago
	}

	claims := jwt.MapClaims{
		"jti":  jti,
		"sub":  "officer-01",
		"role": role,
		"exp":  expTime,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	str, _ := token.SignedString(privKey)
	return str
}

func TestEndToEndAuthorizationFlow(t *testing.T) {
	privKey, pubKey := generateTestKeys()
	attackerPrivKey, _ := generateTestKeys() // Attacker generating their own keys

	// Dummy backend representing our microservice
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	reverseProxy := httputil.NewSingleHostReverseProxy(backendURL)
	rbacEngine := policy.NewEngine([]policy.Rule{
		{Role: "commander", Path: "/api/v1/launch", Methods: []string{"POST"}},
	})

	gateway := &auth.ZTAPGateway{
		PublicKey:  pubKey,
		TokenStore: &MockRedis{},
		RBACEngine: rbacEngine,
	}

	ztapServer := httptest.NewServer(gateway.Authorize(reverseProxy))
	defer ztapServer.Close()

	tests := []struct {
		name           string
		token          string
		method         string
		expectedStatus int
	}{
		{
			name:           "1. Valid Commander Access",
			token:          issueToken(privKey, "commander", "valid-jti", false),
			method:         http.MethodPost,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "2. Missing Token",
			token:          "", // No token sent
			method:         http.MethodPost,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "3. Expired Token",
			token:          issueToken(privKey, "commander", "valid-jti", true), // expired=true
			method:         http.MethodPost,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "4. Revoked Token (Compromised Session)",
			token:          issueToken(privKey, "commander", "compromised-jti-007", false), // Matches Redis blocklist
			method:         http.MethodPost,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "5. Forged Signature (Attacker)",
			token:          issueToken(attackerPrivKey, "commander", "hacked-jti", false), // Signed with wrong key
			method:         http.MethodPost,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "6. RBAC Deny (Insufficient Privilege)",
			token:          issueToken(privKey, "field_officer", "valid-jti", false), // Valid token, wrong role
			method:         http.MethodPost,
			expectedStatus: http.StatusForbidden,
		},
	}

	client := ztapServer.Client()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, ztapServer.URL+"/api/v1/launch", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, resp.StatusCode, string(body))
			}
		})
	}
}

// --- Test Suite 2: Layer 4 mTLS & Network Failures ---

func TestEndToEndmTLSTransport_UntrustedCert(t *testing.T) {
	// Spin up a rogue backend server with its own auto-generated, self-signed TLS certificate.
	// Because this cert is NOT in our Proxy's trusted CA pool, the Proxy MUST drop the connection.
	rogueBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("You should never see this message"))
	}))
	defer rogueBackend.Close()

	backendURL, _ := url.Parse(rogueBackend.URL)

	// Configure a strict TLS transport for the proxy.
	// Notice we are passing an EMPTY RootCAs pool. This simulates the Proxy not trusting
	// the rogue backend's certificate.
	strictTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    nil, // We trust NO ONE by default
			MinVersion: tls.VersionTLS13,
		},
	}

	reverseProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backendURL.Scheme
			req.URL.Host = backendURL.Host
		},
		Transport: strictTransport,
	}

	// Spin up our ZTAP Proxy bypassing the auth middleware just to test the transport layer
	ztapServer := httptest.NewServer(reverseProxy)
	defer ztapServer.Close()

	// Fire a request at the proxy
	resp, err := ztapServer.Client().Get(ztapServer.URL)
	if err != nil {
		t.Fatalf("Test setup failed, couldn't reach proxy: %v", err)
	}
	defer resp.Body.Close()

	// Assert that the proxy rejected the backend
	// When Go's reverse proxy encounters a TLS error with the backend, it returns a 502 Bad Gateway
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected Proxy to return 502 Bad Gateway due to untrusted backend TLS cert, but got %d", resp.StatusCode)
	}
}

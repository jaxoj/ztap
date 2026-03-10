package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"ztap/internal/auth"
	"ztap/internal/policy"

	"github.com/golang-jwt/jwt"
)

type MockTokenStore struct {
	revoked map[string]bool
}

func (m *MockTokenStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	return m.revoked[jti], nil
}

// Helper: Generate RSA keys for testing
func generateTestRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return privateKey, &privateKey.PublicKey
}

func generateRSAToken(privateKey *rsa.PrivateKey, jti, role, sub string, expired bool) string {
	claims := jwt.MapClaims{
		"jti":  jti,
		"role": role,
		"sub":  sub,
	}

	if expired {
		claims["exp"] = jwt.TimeFunc().Add(-1 * time.Hour).Unix() // Expired 1 hour ago
	} else {
		claims["exp"] = jwt.TimeFunc().Add(1 * time.Hour).Unix() // Expires in 1 hour
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)
	return tokenString
}

func TestZTAPGetway_Authorize(t *testing.T) {
	// Generate RSA keys for testing
	privateKey, publicKey := generateTestRSAKeys()
	attackerPrivKey, _ := generateTestRSAKeys() // Simulating a forged key

	mockStore := &MockTokenStore{
		revoked: map[string]bool{
			"revoked-jti-001": true, // this specific token id is blacklisted
		},
	}

	rules := []policy.Rule{
		{Role: "field_officer", Path: "^/api/v1/intel$", Methods: []string{"GET"}, Backend: "https://mock-backend"},
		{Role: "commander", Path: "^/api/v1/launch$", Methods: []string{"POST"}, Backend: "https://mock-backend"},
	}

	rbacEngine, err := policy.NewEngine(rules)
	if err != nil {
		t.Fatalf("Failed to initialize RBAC engine: %v", err)
	}

	gateway := &auth.ZTAPGateway{
		PublicKey:  publicKey,
		TokenStore: mockStore,
		RBACEngine: rbacEngine,
	}

	// dummy backend service to chach successful requests
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	middleware := gateway.Authorize(nextHandler)

	// define the table driven tests
	tests := []struct {
		name           string
		token          string
		method         string
		path           string
		expectedStatus int
	}{
		{
			name:           "Missing Token",
			token:          "",
			method:         http.MethodGet,
			path:           "/api/v1/intel",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Forged Signature (Attacker)",
			token:          generateRSAToken(attackerPrivKey, "valid-jti", "commander", "attacker", false),
			method:         http.MethodPost,
			path:           "/api/v1/launch",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Expired Token",
			token:          generateRSAToken(privateKey, "valid-jti", "commander", "sub-123", true),
			method:         http.MethodPost,
			path:           "/api/v1/launch",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Revoked Token (Logged Out / Compromised)",
			token:          generateRSAToken(privateKey, "revoked-jti-001", "commander", "sub-123", false),
			method:         http.MethodPost,
			path:           "/api/v1/launch",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Valid Token, Insufficient Permissions (RBAC Deny)",
			token:          generateRSAToken(privateKey, "valid-jti", "field_officer", "sub-123", false),
			method:         http.MethodPost, // Field officer trying to launch
			path:           "/api/v1/launch",
			expectedStatus: http.StatusForbidden, // 403 Forbidden
		},
		{
			name:           "Valid Token, Authorized (Success)",
			token:          generateRSAToken(privateKey, "valid-jti", "commander", "sub-123", false),
			method:         http.MethodPost, // Commander launching
			path:           "/api/v1/launch",
			expectedStatus: http.StatusOK, // 200 OK
		},
	}

	// 6. Execute Tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rec := httptest.NewRecorder()

			middleware.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Test '%s' failed: Expected status %d, got %d", tt.name, tt.expectedStatus, rec.Code)
			}
		})
	}
}

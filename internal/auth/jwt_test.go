package auth_test

import (
	"testing"
	"time"
	"ztap/internal/auth"

	"github.com/golang-jwt/jwt/v5"
)

// secret key for test environment - in production, this should be stored securely and not hardcoded
var testSecretKey = []byte("super-secret-military-grade-key")

func generateTestToken(valid bool, expired bool) string {
	claims := jwt.MapClaims{
		"sub":  "officer-123",
		"role": "field-officer",
	}

	if expired {
		claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	} else {
		claims["exp"] = time.Now().Add(1 * time.Hour).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	key := testSecretKey
	if !valid {
		key = []byte("wrong-key-attacker")
	}

	tokenStr, _ := token.SignedString(key)
	return tokenStr
}

func TestValidateToken(t *testing.T) {
	t.Run("Valid Token", func(t *testing.T) {
		tokenStr := generateTestToken(true, false)
		_, err := auth.ValidateToken(tokenStr, testSecretKey)
		if err != nil {
			t.Errorf("Expected valid token, got error: %v", err)
		}
	})

	t.Run("Expired Token", func(t *testing.T) {
		tokenStr := generateTestToken(true, true) // Valid signiture bu expired
		_, err := auth.ValidateToken(tokenStr, testSecretKey)
		if err == nil {
			t.Errorf("Expected error for expired token, got nil")
		}
	})

	t.Run("Invalid Token", func(t *testing.T) {
		tokenStr := generateTestToken(false, false) // Invalid signature
		_, err := auth.ValidateToken(tokenStr, testSecretKey)
		if err == nil {
			t.Errorf("Expected error for invalid token, got nil")
		}
	})

}

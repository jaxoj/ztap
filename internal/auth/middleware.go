package auth

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"
	"ztap/internal/policy"
)

// Define a custom type for context keys to avoid collisions
type contextKey string

const RoleContextKey contextKey = "role"
const SubContextKey contextKey = "sub"

// ZTAPGateway holds the dependencies for our proxy middleware
type ZTAPGateway struct {
	PublicKey  *rsa.PublicKey
	TokenStore TokenStore
	RBACEngine *policy.Engine
}

// Authorize is final middleware that inforces zero-trust principles
func (g *ZTAPGateway) Authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Missing Authorization Header", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Verify RSA signiture, expiration and redis revocation status
		claims, err := ValidateRSAToken(r.Context(), tokenString, g.PublicKey, g.TokenStore)
		if err != nil {
			http.Error(w, "ZTAP Denied: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Extract role and subject for RBAC check
		role, _ := claims["role"].(string)
		sub, _ := claims["sub"].(string)

		if !g.RBACEngine.IsAllowed(role, r.URL.Path, r.Method) {
			http.Error(w, "ZTAP Denied: Insufficient clearence for this opperation", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), RoleContextKey, role)
		ctx = context.WithValue(ctx, SubContextKey, sub)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

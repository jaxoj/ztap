package auth

import (
	"context"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

// TokenStore defines how we check token states (e.g redis)
type TokenStore interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// ValidateRSAToken verifies the RSA signature, expiration, and checks Redis for revocation.
func ValidateRSAToken(ctx context.Context, tokenString string, publicKey *rsa.PublicKey, store TokenStore) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	// Extract the JWT ID (jti) to check agianst redis
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return nil, jwt.ErrSignatureInvalid
	}

	// Check Redis to see if the token was revoked (e.g., user logged out or compromised)
	isRevoked, err := store.IsRevoked(ctx, jti)
	if err != nil {
		return nil, err
	}
	if isRevoked {
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}

// ValidateToken parses and mathematically verifies the JWT signature and expiration.
func ValidateToken(tokenStr string, secretKey []byte) (map[string]interface{}, error) {
	// Parse the token and supply the key function
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is what we expect (HMAC in this case)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		// double check the signing method is exactly HS256
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, jwt.ErrSignatureInvalid
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	// Extract claims if the token is valid
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	privPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback for older PKCS1 format
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}
	return priv.(*rsa.PrivateKey), nil
}

func main() {
	role := flag.String("role", "commander", "The RBAC role to embed in the token")
	jti := flag.String("jti", fmt.Sprintf("txn-%d", time.Now().Unix()), "The unique JWT ID")
	duration := flag.Int("mins", 60, "Token validity duration in minutes")
	flag.Parse()

	// Load the Identity Provider's private key (Must match the public key in the proxy!)
	privKey, err := loadPrivateKey("certs/ztap_private.pem")
	if err != nil {
		log.Fatalf("Fatal: Could not load private key: %v", err)
	}

	claims := jwt.MapClaims{
		"sub":  "test-officer",
		"role": *role,
		"jti":  *jti,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Duration(*duration) * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privKey)
	if err != nil {
		log.Fatalf("Fatal: Failed to sign token: %v", err)
	}

	fmt.Println("\n=== ZERO-TRUST ACCESS TOKEN GENERATED ===")
	fmt.Printf("Role: %s\n", *role)
	fmt.Printf("Expires In: %d minutes\n", *duration)
	fmt.Println("-----------------------------------------")
	fmt.Printf("Bearer %s\n", signedToken)
	fmt.Println("-----------------------------------------")
	fmt.Println("Usage: curl -k -H \"Authorization: Bearer <token>\" https://localhost")
}

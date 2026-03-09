package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
	"ztap/internal/auth"
	"ztap/internal/policy"
	"ztap/internal/proxy"
	"ztap/internal/storage"

	"github.com/joho/godotenv"
)

// Helper function to load the Identity Provider's RSA Public Key from disk
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	pubPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("key type is not RSA")
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Printf(".ENV file not found %v", err)
	}
	log.Printf("Initializing Zero-Trust Access Poxy (ZTAP)...")

	// ==========================================
	// 1. Load the Identity Provider's Public Key
	// ==========================================
	// This is used to mathematically verify JWT signatures.
	publicKey, err := loadPublicKey(os.Getenv("RSA_PUBLIC_KEY_PATH"))
	if err != nil {
		log.Fatalf("Fatal: Could not load IdP public key: %v", err)
	}

	// ==========================================
	// 2. Connect to the Stateful Token Cache (Redis)
	// ==========================================
	// Used for instantly revoking compromised sessions.
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379/0" // Default for local testing
	}
	redisStore, err := storage.NewRedisStore(redisURL)
	if err != nil {
		log.Fatalf("Fatal: Could not connect to Redis: %v", err)
	}
	log.Println("Connected to Redis revocation store.")

	rbacConfig, err := policy.LoadFromYAML(os.Getenv("RBAC_POLICY_PATH"))
	if err != nil {
		log.Fatalf("Fatal: Could not load RBAC policies: %v", err)
	}
	rbacEngine := policy.NewEngine(rbacConfig.Policies)
	log.Println("RBAC policies loaded successfully.")

	// ==========================================
	// 4. Configure the mTLS Network Transport
	// ==========================================
	// This ensures we encrypt traffic to the microservices and prove our identity.
	mtlsTransport, err := proxy.NewMTLSTransport(
		os.Getenv("ROOT_CA_PATH"),    // Root CA
		os.Getenv("PROXY_CERT_PATH"), // ZTAP's Client Cert
		os.Getenv("PROXY_KEY_PATH"),  // ZTAP's Private Key
	)
	if err != nil {
		log.Fatalf("Fatal: Could not configure mTLS transport: %v", err)
	}

	// ==========================================
	// 5. Initialize the Core Reverse Proxy
	// ==========================================
	// Define where authorized traffic should be forwarded.
	targetURL, _ := url.Parse("https://localhost:8443") // The protected internal microservice
	reverseProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Rewrite the request to point to the backend microservice
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Host = targetURL.Host
		},
		Transport: mtlsTransport, // Inject our military-grade mTLS transport here!
	}

	// ==========================================
	// 6. Wrap the Proxy in our ZTAP Middleware
	// ==========================================
	gateway := &auth.ZTAPGateway{
		PublicKey:  publicKey,
		TokenStore: redisStore,
		RBACEngine: rbacEngine,
	}

	// The actual HTTP handler: First Authorize, then Proxy.
	secureHandler := gateway.Authorize(reverseProxy)

	// ==========================================
	// 7. Start the Secure HTTPS Server
	// ==========================================
	server := &http.Server{
		Addr:         ":443", // Standard HTTPS port
		Handler:      secureHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Println("ZTAP Gateway is listening on port 443 (HTTPS)...")
	// ZTAP itself listens on TLS using its own server certificates (front-end encryption)
	err = server.ListenAndServeTLS(os.Getenv("SERVER_CERT_PATH"), os.Getenv("SERVER_KEY_PATH"))
	if err != nil {
		log.Fatalf("Fatal: Server crashed: %v", err)
	}
}

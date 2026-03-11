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
	log.Println(os.Environ())
	log.Printf("Initializing Zero-Trust Access Poxy (ZTAP)...")

	// ==========================================
	// Load the Identity Provider's Public Key
	// ==========================================
	// This is used to mathematically verify JWT signatures.
	publicKey, err := loadPublicKey(os.Getenv("RSA_PUBLIC_KEY_PATH"))
	if err != nil {
		log.Fatalf("Fatal: Could not load IdP public key: %v", err)
	}

	// ==========================================
	// Connect to the Stateful Token Cache (Redis)
	// ==========================================
	// Used for instantly revoking compromised sessions.
	redisURL := os.Getenv("REDIS_STORE_URL")
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
	rbacEngine, err := policy.NewEngine(rbacConfig.Policies)
	if err != nil {
		log.Fatalf("Fatal: Could not initialize RBAC engine: %v", err)
	}
	log.Println("RBAC policies loaded successfully.")

	// ==========================================
	// Configure the mTLS Network Transport
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
	// Initialize the Dynamic Reverse Proxy
	// ==========================================
	// Define where authorized traffic should be forwarded.
	reverseProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Pull the dynamic backend URL from the context
			targetRaw, ok := req.Context().Value(auth.TargetContextKey).(string)
			if !ok {
				log.Println("Error: No target backend found in context")
				return
			}

			target, err := url.Parse(targetRaw)
			if err != nil {
				log.Printf("Error parsing backend URL %s: %v", targetRaw, err)
				return
			}

			// Rewrite the request for the specific microservice
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
		},
		Transport: mtlsTransport,
	}

	// ==========================================
	// Wrap the Proxy in our ZTAP Middleware
	// ==========================================
	gateway := &auth.ZTAPGateway{
		PublicKey:  publicKey,
		TokenStore: redisStore,
		RBACEngine: rbacEngine,
	}

	// The actual HTTP handler: First Authorize, then Proxy.
	secureHandler := gateway.Authorize(reverseProxy)

	// ==========================================
	// Start the Secure HTTPS Server
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
	err = server.ListenAndServeTLS(os.Getenv("PROXY_CERT_PATH"), os.Getenv("PROXY_KEY_PATH"))
	if err != nil {
		log.Fatalf("Fatal Server crashed: %v", err)
	}
}

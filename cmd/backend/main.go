package backend

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
)

func main() {
	log.Printf("Starting Highly Classified Internal Microservice ...")

	// Load the internal CA that signed the ZTAP Proxy's certificate
	caCert, err := os.ReadFile("../../certs/ca.crt")
	if err != nil {
		log.Fatalf("Fetal: Failed to load CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Configure strict mTLS settings to only trust the ZTAP Proxy's certificate
	tlsConfig := &tls.Config{
		// RequireAndVerifyClientCert is the magic flag for backend mTLS!
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	// Define the protected endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/launch", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Target Locked, Launch Sequence Initiated."))
	})

	server := &http.Server{
		Addr:      ":8443", // Internal secure port
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Println("Backend listening on port 8443. Demanding mTLS from clients...")
	// The backend needs its own certificate to prove its identity to the proxy
	err = server.ListenAndServeTLS("../../certs/backend.crt", "../../certs/backend.key")
	if err != nil {
		log.Fatalf("Backend server crashed: %v", err)
	}
}

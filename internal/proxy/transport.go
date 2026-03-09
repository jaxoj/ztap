package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
)

// NewMTLSTransport creates an http.RoundTripper configured for strict Mutual TLS.
func NewMTLSTransport(caPath, clientCertPath, clientKeyPath string) (http.RoundTripper, error) {
	// Load the ca certificate to verify the backend microservice
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("failed to append CA certificate")
	}

	// Load the ZTAP's Proxy's own certificate and private key to present to the backend
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert}, // Present this to backend
		RootCAs:      caCertPool,                    // Only trust backends signed by our CA
		MinVersion:   tls.VersionTLS13,              // Force modern cryptography
	}

	// Attach it to a custom HTTP transport
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		// Performance tuning for microservices
		MaxIdleConns:          100,
		IdleConnTimeout:       90,
		TLSHandshakeTimeout:   10,
		ExpectContinueTimeout: 1,
	}

	return transport, nil
}

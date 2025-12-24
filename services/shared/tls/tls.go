// Package tls provides TLS configuration and utilities for secure communication.
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// Config holds TLS configuration options.
type Config struct {
	// CertFile is the path to the TLS certificate file.
	CertFile string
	// KeyFile is the path to the TLS private key file.
	KeyFile string
	// CAFile is the path to the CA certificate file for client verification.
	CAFile string
	// ClientAuth specifies the client authentication policy.
	ClientAuth tls.ClientAuthType
	// MinVersion is the minimum TLS version (default: TLS 1.2).
	MinVersion uint16
	// InsecureSkipVerify skips certificate verification (for testing only).
	InsecureSkipVerify bool
}

// DefaultConfig returns a TLS config with secure defaults.
func DefaultConfig() *Config {
	return &Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.NoClientCert,
	}
}

// ServerTLSConfig creates a tls.Config for servers.
func ServerTLSConfig(cfg *Config) (*tls.Config, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("certificate and key files are required")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   cfg.MinVersion,
		ClientAuth:   cfg.ClientAuth,
		CipherSuites: preferredCipherSuites(),
	}

	// Load CA for client certificate verification if provided
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caPool
		if cfg.ClientAuth == tls.NoClientCert {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	return tlsConfig, nil
}

// ClientTLSConfig creates a tls.Config for clients.
func ClientTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         cfg.MinVersion,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	// Load client certificate if provided
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA for server verification if provided
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caPool
	}

	return tlsConfig, nil
}

// GRPCServerTLSConfig creates TLS credentials for gRPC servers.
func GRPCServerTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsConfig, err := ServerTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Enable HTTP/2 for gRPC
	tlsConfig.NextProtos = []string{"h2"}

	return tlsConfig, nil
}

// GRPCClientTLSConfig creates TLS credentials for gRPC clients.
func GRPCClientTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsConfig, err := ClientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Enable HTTP/2 for gRPC
	tlsConfig.NextProtos = []string{"h2"}

	return tlsConfig, nil
}

// preferredCipherSuites returns a list of secure cipher suites.
func preferredCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
}

// GenerateSelfSignedCert generates a self-signed certificate for testing.
// This should NOT be used in production.
func GenerateSelfSignedCert(hosts []string) (certPEM, keyPEM []byte, err error) {
	// Implementation would use crypto/x509 to generate a self-signed cert
	// For production, use proper CA-signed certificates
	return nil, nil, fmt.Errorf("use 'make generate-keys' or a proper CA for certificates")
}

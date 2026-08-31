package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// issueServer writes a certificate carrying only the serverAuth extended key
// usage. Server and client certificates are kept strictly separate so that a
// missing extended key usage shows up here rather than in production.
func issueServer(ca *authority, dir string, names []string, ttl time.Duration) (string, error) {
	tmpl := leafTemplate(names[0], ttl)
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, name)
	}
	return issue(ca, dir, names[0], tmpl)
}

// issueClient writes a certificate carrying only the clientAuth extended key
// usage. No subject alternative name is set: the common name is the identifier
// that proxies and access logs record.
func issueClient(ca *authority, dir, cn string, ttl time.Duration) (string, error) {
	tmpl := leafTemplate(cn, ttl)
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	return issue(ca, dir, cn, tmpl)
}

func leafTemplate(cn string, ttl time.Duration) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
}

func issue(ca *authority, dir, name string, tmpl *x509.Certificate) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	serial, err := newSerial()
	if err != nil {
		return "", err
	}
	tmpl.SerialNumber = serial

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return "", err
	}

	certPath := filepath.Join(dir, name+".crt")
	if err := writeCert(certPath, der); err != nil {
		return "", err
	}
	if err := writeKey(filepath.Join(dir, name+".key"), key); err != nil {
		return "", err
	}
	return certPath, nil
}

func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

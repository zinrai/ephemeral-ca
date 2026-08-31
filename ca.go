package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// loadOrCreateCA reuses the CA in dir when both files are present, and creates
// one when neither is. A half present CA is an error rather than a silent
// overwrite: the existing key may already have signed certificates in use.
func loadOrCreateCA(dir string, ttl time.Duration) (*authority, bool, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	switch {
	case certExists && keyExists:
		ca, err := loadCA(certPath, keyPath)
		return ca, false, err
	case certExists != keyExists:
		return nil, false, fmt.Errorf("incomplete CA in %s: found one of %s and %s but not both", dir, caCertFile, caKeyFile)
	}

	if ttl <= 0 {
		return nil, false, errors.New("-ca-ttl must be positive")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, false, err
	}

	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		return nil, false, err
	}

	now := time.Now()
	// No whitespace in the CN: configuration that authorizes by issuing CA
	// treats the CN as one whitespace-delimited value.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ephemeral-ca-root-" + hex.EncodeToString(suffix)},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, false, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false, err
	}

	if err := writeCert(certPath, der); err != nil {
		return nil, false, err
	}
	if err := writeKey(keyPath, key); err != nil {
		return nil, false, err
	}
	return &authority{cert: cert, key: key}, true, nil
}

func loadCA(certPath, keyPath string) (*authority, error) {
	cert, err := readCert(certPath)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%s is not a CA certificate", certPath)
	}
	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("CA in %s expired at %s: delete the directory and start over",
			filepath.Dir(certPath), cert.NotAfter.Format(time.RFC3339))
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("%s does not contain a PEM EC private key", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, key: key}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

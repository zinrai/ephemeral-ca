package main

import (
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"
)

// A server certificate is valid for server authentication and nothing else.
func TestServerCertificateVerifiesOnlyAsServer(t *testing.T) {
	dir := t.TempDir()
	err := run(config{out: dir, server: "example.test,localhost,127.0.0.1", ttl: time.Hour, caTTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	cert, err := readCert(filepath.Join(dir, "server", "example.test.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAgainstCA(t, dir, cert, x509.ExtKeyUsageServerAuth); err != nil {
		t.Errorf("server certificate does not verify for server authentication: %v", err)
	}
	if err := verifyAgainstCA(t, dir, cert, x509.ExtKeyUsageClientAuth); err == nil {
		t.Error("server certificate verifies for client authentication")
	}

	if cert.Subject.CommonName != "example.test" {
		t.Errorf("common name = %q, want the first -server value %q", cert.Subject.CommonName, "example.test")
	}
	wantDNS := []string{"example.test", "localhost"}
	if len(cert.DNSNames) != len(wantDNS) || cert.DNSNames[0] != wantDNS[0] || cert.DNSNames[1] != wantDNS[1] {
		t.Errorf("DNS SANs = %v, want %v", cert.DNSNames, wantDNS)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IP SANs = %v, want [127.0.0.1]", cert.IPAddresses)
	}
}

// A client certificate is valid for client authentication and nothing else,
// and its common name is its sole identifier.
func TestClientCertificateVerifiesOnlyAsClient(t *testing.T) {
	dir := t.TempDir()
	err := run(config{out: dir, clients: "alice", ttl: time.Hour, caTTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	cert, err := readCert(filepath.Join(dir, "clients", "alice.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAgainstCA(t, dir, cert, x509.ExtKeyUsageClientAuth); err != nil {
		t.Errorf("client certificate does not verify for client authentication: %v", err)
	}
	if err := verifyAgainstCA(t, dir, cert, x509.ExtKeyUsageServerAuth); err == nil {
		t.Error("client certificate verifies for server authentication")
	}

	if cert.Subject.CommonName != "alice" {
		t.Errorf("common name = %q, want %q", cert.Subject.CommonName, "alice")
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 {
		t.Errorf("client certificate carries SANs (DNS %v, IP %v), want none", cert.DNSNames, cert.IPAddresses)
	}
}

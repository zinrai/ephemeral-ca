package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A second run against the same directory signs with the existing CA, so
// certificates from both runs verify against one ca.crt.
func TestSecondRunSignsWithTheSameCA(t *testing.T) {
	dir := t.TempDir()
	if err := run(config{out: dir, clients: "alice", ttl: time.Hour, caTTL: 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	caBefore, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}

	if err := run(config{out: dir, clients: "bob", ttl: time.Hour}); err != nil {
		t.Fatal(err)
	}
	caAfter, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(caBefore) != string(caAfter) {
		t.Fatal("second run replaced ca.crt")
	}

	for _, name := range []string{"alice", "bob"} {
		cert, err := readCert(filepath.Join(dir, "clients", name+".crt"))
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyAgainstCA(t, dir, cert, x509.ExtKeyUsageClientAuth); err != nil {
			t.Errorf("%s does not verify against the shared CA: %v", name, err)
		}
	}
}

// The CA common name contains no whitespace, so configuration that names an
// issuing CA can treat it as a single value.
func TestCACommonNameContainsNoWhitespace(t *testing.T) {
	dir := t.TempDir()
	if err := run(config{out: dir, clients: "alice", ttl: time.Hour, caTTL: 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	caCert, err := readCert(filepath.Join(dir, caCertFile))
	if err != nil {
		t.Fatal(err)
	}
	if cn := caCert.Subject.CommonName; strings.ContainsAny(cn, " \t") {
		t.Errorf("CA common name %q contains whitespace", cn)
	}
}

// verifyAgainstCA answers whether the CA in dir vouches for cert for the
// given usage, judged by the same chain building a TLS peer would do.
func verifyAgainstCA(t *testing.T, dir string, cert *x509.Certificate, usage x509.ExtKeyUsage) error {
	t.Helper()
	caCert, err := readCert(filepath.Join(dir, caCertFile))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{usage},
	})
	return err
}

// A certificate that would outlive the CA is refused instead of issued.
func TestCertificateOutlivingTheCAIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := run(config{out: dir, clients: "alice", ttl: 30 * time.Minute, caTTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := run(config{out: dir, clients: "dave", ttl: 2 * time.Hour}); err == nil {
		t.Fatal("issued a certificate that outlives the CA")
	}
	if _, err := os.Stat(filepath.Join(dir, "clients", "dave.crt")); err == nil {
		t.Fatal("dave.crt was written despite the error")
	}
}

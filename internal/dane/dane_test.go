package dane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// selfSigned builds a throwaway leaf certificate for testing.
func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestTLSAValue(t *testing.T) {
	cert := selfSigned(t)
	got := tlsaValue(cert)
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	want := "3 1 1 " + hex.EncodeToString(sum[:])
	if got != want {
		t.Errorf("tlsaValue = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, "3 1 1 ") || len(got) != len("3 1 1 ")+64 {
		t.Errorf("unexpected TLSA shape: %q", got)
	}
}

func TestCertFromFile(t *testing.T) {
	cert := selfSigned(t)
	path := filepath.Join(t.TempDir(), "cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := certFromFile(path)
	if err != nil {
		t.Fatalf("certFromFile: %v", err)
	}
	if tlsaValue(got) != tlsaValue(cert) {
		t.Error("round-tripped cert produced a different TLSA value")
	}

	// A file with no CERTIFICATE block is an error.
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := certFromFile(bad); err == nil {
		t.Error("expected error for non-cert file")
	}
}

func TestValuePrefersFile(t *testing.T) {
	cert := selfSigned(t)
	path := filepath.Join(t.TempDir(), "cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Value(t.Context(), path, "mail.example.com")
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if res.Value != tlsaValue(cert) {
		t.Errorf("Value = %q, want %q", res.Value, tlsaValue(cert))
	}
	if res.Source != "file:"+path {
		t.Errorf("Source = %q, want file:%s", res.Source, path)
	}
}

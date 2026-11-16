package selfupdate

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// The testdata pair is the SHA256SUMS of release v1.43.24 with its detached signature.
func loadSumsPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	sums, err := os.ReadFile("testdata/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile("testdata/SHA256SUMS.asc")
	if err != nil {
		t.Fatal(err)
	}
	return sums, sig
}

func TestVerifySumsAcceptsPinnedSignature(t *testing.T) {
	sums, sig := loadSumsPair(t)
	if err := verifySums(sums, sig); err != nil {
		t.Fatalf("valid release signature rejected: %v", err)
	}
}

func TestVerifySumsRejectsTamperedBody(t *testing.T) {
	sums, sig := loadSumsPair(t)
	bad := bytes.Replace(sums, []byte("mailadmin-linux-amd64"), []byte("mailadmin-linux-amd65"), 1)
	if bytes.Equal(bad, sums) {
		t.Fatal("test setup: nothing replaced")
	}
	err := verifySums(bad, sig)
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered SHA256SUMS accepted or wrong error: %v", err)
	}
}

func TestVerifySumsRejectsWrongSignature(t *testing.T) {
	sums, sig := loadSumsPair(t)
	// Signature over other bytes does not match the body.
	if err := verifySums([]byte(strings.Repeat("x", 64)+"\n"), sig); err == nil {
		t.Fatal("signature accepted for different content")
	}
	if err := verifySums(sums, []byte("not a signature")); err == nil {
		t.Fatal("garbage signature accepted")
	}
}

func TestSignatureURLRequired(t *testing.T) {
	_, err := signatureURL([]Asset{{Name: "SHA256SUMS", URL: "https://x/SHA256SUMS"}})
	if !errors.Is(err, ErrUnsigned) {
		t.Fatalf("release without .asc not refused: %v", err)
	}
}

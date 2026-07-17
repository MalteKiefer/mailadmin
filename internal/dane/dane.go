// Package dane derives inbound-SMTP DANE TLSA records (RFC 7672) for a mail
// host from its TLS certificate. It emits DANE-EE / SPKI / SHA-256 ("3 1 1")
// values, pinning the certificate's public key — the common choice for SMTP.
//
// The certificate is taken from a local PEM file when a path is given, else read
// live from the host via SMTP STARTTLS on port 25 (what a DANE verifier sees).
// A "3 1 1" value pins the public key, so it survives a certificate renewal only
// when the key is reused (e.g. certbot --reuse-key); otherwise republish on
// rotation.
package dane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"time"
)

// SMTPPort is the inbound SMTP port DANE TLSA records are published for.
const SMTPPort = 25

// tlsaValue renders the "3 1 1" TLSA value for a certificate: cert usage 3
// (DANE-EE), selector 1 (SubjectPublicKeyInfo), matching type 1 (SHA-256).
func tlsaValue(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "3 1 1 " + hex.EncodeToString(sum[:])
}

// Result is a derived TLSA record value plus where the certificate came from.
type Result struct {
	Value  string // e.g. "3 1 1 <hex>"
	Source string // "file:<path>" or "starttls:<host>:25"
}

// Value derives the TLSA value for host, preferring the PEM at certPath and
// falling back to a live STARTTLS read when certPath is empty.
func Value(ctx context.Context, certPath, host string) (Result, error) {
	if certPath != "" {
		cert, err := certFromFile(certPath)
		if err != nil {
			return Result{}, fmt.Errorf("dane: read cert %s: %w", certPath, err)
		}
		return Result{Value: tlsaValue(cert), Source: "file:" + certPath}, nil
	}
	cert, err := certFromSTARTTLS(ctx, host)
	if err != nil {
		return Result{}, fmt.Errorf("dane: fetch cert from %s:%d: %w", host, SMTPPort, err)
	}
	return Result{Value: tlsaValue(cert), Source: fmt.Sprintf("starttls:%s:%d", host, SMTPPort)}, nil
}

// certFromFile reads the first (leaf) certificate from a PEM bundle.
func certFromFile(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured cert path
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
	return nil, fmt.Errorf("no CERTIFICATE block found")
}

// certFromSTARTTLS opens an SMTP session to host:25, upgrades via STARTTLS, and
// returns the leaf certificate the server presents. TLS verification is skipped
// on purpose: DANE pins the presented cert, so this only needs to read it.
func certFromSTARTTLS(ctx context.Context, host string) (*x509.Certificate, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(SMTPPort)))
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer func() { _ = c.Close() }()
	// #nosec G402 -- DANE reads the presented cert; it does not trust the chain.
	if err := c.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true}); err != nil {
		return nil, err
	}
	state, ok := c.TLSConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificate presented")
	}
	return state.PeerCertificates[0], nil
}

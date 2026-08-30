package bimi

import (
	"errors"
	"strings"
	"testing"
)

const validTinyPS = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <circle cx="50" cy="50" r="40" fill="#000"/>
</svg>`

func TestValidateSVG_Valid(t *testing.T) {
	if err := ValidateSVG([]byte(validTinyPS)); err != nil {
		t.Fatalf("expected valid tiny-ps svg to pass, got: %v", err)
	}
}

func TestValidateSVG_Empty(t *testing.T) {
	if err := ValidateSVG(nil); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestValidateSVG_NotXML(t *testing.T) {
	if err := ValidateSVG([]byte("not xml at all")); err == nil {
		t.Fatal("expected error for malformed XML")
	}
}

func TestValidateSVG_WrongRoot(t *testing.T) {
	if err := ValidateSVG([]byte(`<svgx baseProfile="tiny-ps"/>`)); err == nil {
		t.Fatal("expected error for non-svg root element")
	}
}

func TestValidateSVG_MissingBaseProfile(t *testing.T) {
	err := ValidateSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"></svg>`))
	if err == nil {
		t.Fatal("expected error for missing baseProfile")
	}
	if !strings.Contains(err.Error(), "baseProfile") {
		t.Fatalf("expected error to mention baseProfile, got: %v", err)
	}
}

func TestValidateSVG_WrongBaseProfile(t *testing.T) {
	err := ValidateSVG([]byte(`<svg baseProfile="full"></svg>`))
	if err == nil {
		t.Fatal("expected error for wrong baseProfile")
	}
}

func TestValidateSVG_TooLarge(t *testing.T) {
	huge := make([]byte, maxSVGBytes+1)
	for i := range huge {
		huge[i] = 'a'
	}
	if err := ValidateSVG(huge); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got: %v", err)
	}
}

func TestBuildRecord_LogoOnly(t *testing.T) {
	rec, err := BuildRecord("https://example.com/logo.svg", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Name != "default._bimi" {
		t.Errorf("name = %q, want default._bimi", rec.Name)
	}
	want := "v=BIMI1; l=https://example.com/logo.svg;"
	if rec.Content != want {
		t.Errorf("content = %q, want %q", rec.Content, want)
	}
}

func TestBuildRecord_LogoAndVMC(t *testing.T) {
	rec, err := BuildRecord("https://example.com/logo.svg", "https://example.com/vmc.pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem;"
	if rec.Content != want {
		t.Errorf("content = %q, want %q", rec.Content, want)
	}
}

func TestBuildRecord_MissingLogo(t *testing.T) {
	if _, err := BuildRecord("", ""); err == nil {
		t.Fatal("expected error for missing logo url")
	}
}

func TestBuildRecord_RejectsHTTP(t *testing.T) {
	if _, err := BuildRecord("http://example.com/logo.svg", ""); err == nil {
		t.Fatal("expected error for non-https logo url")
	}
}

func TestBuildRecord_RejectsHTTPVMC(t *testing.T) {
	if _, err := BuildRecord("https://example.com/logo.svg", "http://example.com/vmc.pem"); err == nil {
		t.Fatal("expected error for non-https vmc url")
	}
}

func TestBuildRecord_RejectsMalformedURL(t *testing.T) {
	if _, err := BuildRecord("https://ex ample.com/logo.svg", ""); err == nil {
		t.Fatal("expected error for malformed logo url")
	}
}

func TestBuildRecord_RejectsNoHost(t *testing.T) {
	if _, err := BuildRecord("https:///logo.svg", ""); err == nil {
		t.Fatal("expected error for missing host")
	}
}

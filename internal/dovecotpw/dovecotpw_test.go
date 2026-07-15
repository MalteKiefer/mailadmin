package dovecotpw

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePlaintext(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
		want      error
	}{
		{"ok simple", "hunter2", nil},
		{"ok spaces and symbols", "a b$c#d %^&*()", nil},
		{"ok unicode", "pä55wörd-✓", nil},
		{"ok max length", strings.Repeat("x", maxPlaintext), nil},
		{"empty", "", ErrEmptyPassword},
		{"too long", strings.Repeat("x", maxPlaintext+1), ErrTooLong},
		{"newline", "foo\nbar", ErrInvalidPassword},
		{"carriage return", "foo\rbar", ErrInvalidPassword},
		{"nul byte", "foo\x00bar", ErrInvalidPassword},
		{"trailing newline", "foo\n", ErrInvalidPassword},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePlaintext(tt.plaintext)
			if !errors.Is(err, tt.want) {
				t.Fatalf("validatePlaintext(%q) = %v, want %v", tt.plaintext, err, tt.want)
			}
		})
	}
}

func TestStdinPayload(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
		want      string
	}{
		{"simple", "secret", "secret\nsecret\n"},
		{"with spaces", "two words", "two words\ntwo words\n"},
		{"symbols", "p@$$w0rd!", "p@$$w0rd!\np@$$w0rd!\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stdinPayload(tt.plaintext); got != tt.want {
				t.Fatalf("stdinPayload(%q) = %q, want %q", tt.plaintext, got, tt.want)
			}
		})
	}
}

func TestStdinPayloadDeliversTwice(t *testing.T) {
	// doveadm reads the password on two separate prompts; the payload must
	// therefore contain exactly two newline-terminated copies.
	const pw = "correct horse"
	got := stdinPayload(pw)
	lines := strings.Split(got, "\n")
	// "a\na\n" splits into {"a","a",""}.
	if len(lines) != 3 || lines[0] != pw || lines[1] != pw || lines[2] != "" {
		t.Fatalf("stdinPayload(%q) = %q; want two %q lines then empty", pw, got, pw)
	}
}

func TestParseHash(t *testing.T) {
	const argon = "$argon2id$v=19$m=65536,t=3,p=1$c29tZXNhbHQ$aGFzaGVkdmFsdWU"
	tests := []struct {
		name    string
		stdout  string
		want    string
		wantErr error
	}{
		{
			name:   "bare hash",
			stdout: argon + "\n",
			want:   argon,
		},
		{
			name:   "no trailing newline",
			stdout: argon,
			want:   argon,
		},
		{
			name:   "surrounding whitespace",
			stdout: "  " + argon + "  \n",
			want:   argon,
		},
		{
			name:   "scheme-prefixed form",
			stdout: "{ARGON2ID}" + argon + "\n",
			want:   argon,
		},
		{
			name:   "prompt noise before hash",
			stdout: "Enter new password: \nRetype new password: \n" + argon + "\n",
			want:   argon,
		},
		{
			name:    "empty output",
			stdout:  "",
			wantErr: ErrNoHash,
		},
		{
			name:    "only whitespace",
			stdout:  "   \n\n",
			wantErr: ErrNoHash,
		},
		{
			name:    "wrong scheme rejected",
			stdout:  "$2y$10$abcdefghijklmnopqrstuv\n",
			wantErr: ErrNoHash,
		},
		{
			name:    "plaintext echo rejected",
			stdout:  "hunter2\n",
			wantErr: ErrNoHash,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHash(tt.stdout)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("parseHash(%q) err = %v, want %v", tt.stdout, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHash(%q) unexpected err: %v", tt.stdout, err)
			}
			if got != tt.want {
				t.Fatalf("parseHash(%q) = %q, want %q", tt.stdout, got, tt.want)
			}
		})
	}
}

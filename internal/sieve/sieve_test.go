package sieve

import (
	"errors"
	"testing"

	"mailadmin/internal/sys"
	"mailadmin/internal/valid"
)

func TestParseList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []Script
	}{
		{
			name: "empty",
			in:   "",
			want: nil,
		},
		{
			name: "whitespace only",
			in:   "\n  \n\t\n",
			want: nil,
		},
		{
			name: "single inactive",
			in:   "roundcube\n",
			want: []Script{{Name: "roundcube", Active: false}},
		},
		{
			name: "single active",
			in:   "mailadmin (active)\n",
			want: []Script{{Name: "mailadmin", Active: true}},
		},
		{
			name: "mixed with blank lines and CRLF",
			in:   "roundcube\r\n\r\nmailadmin (active)\r\nvacation\r\n",
			want: []Script{
				{Name: "roundcube", Active: false},
				{Name: "mailadmin", Active: true},
				{Name: "vacation", Active: false},
			},
		},
		{
			name: "active marker any case",
			in:   "one (ACTIVE)\ntwo (Active)\n",
			want: []Script{
				{Name: "one", Active: true},
				{Name: "two", Active: true},
			},
		},
		{
			name: "extra spacing around marker",
			in:   "spaced    (active)   \n",
			want: []Script{{Name: "spaced", Active: true}},
		},
		{
			name: "name containing the word active is not a marker",
			in:   "myactive\n",
			want: []Script{{Name: "myactive", Active: false}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseList(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("parseList(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i].Name != tt.want[i].Name || got[i].Active != tt.want[i].Active {
					t.Errorf("parseList(%q)[%d] = %#v, want %#v", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestTrimActiveSuffix(t *testing.T) {
	tests := []struct {
		in       string
		wantName string
		wantOK   bool
	}{
		{"mailadmin (active)", "mailadmin", true},
		{"mailadmin (ACTIVE)", "mailadmin", true},
		{"mailadmin   (active)", "mailadmin", true},
		{"plain", "plain", false},
		{"(active)", "", true},
		{"short", "short", false},
		{"", "", false},
		{"weird(activeish)", "weird(activeish)", false},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			name, ok := trimActiveSuffix(tt.in)
			if ok != tt.wantOK || name != tt.wantName {
				t.Errorf("trimActiveSuffix(%q) = (%q,%v), want (%q,%v)", tt.in, name, ok, tt.wantName, tt.wantOK)
			}
		})
	}
}

func TestActiveScript(t *testing.T) {
	tests := []struct {
		name     string
		in       []Script
		wantName string
		wantOK   bool
	}{
		{"none", []Script{{Name: "a"}, {Name: "b"}}, "", false},
		{"empty", nil, "", false},
		{"one active", []Script{{Name: "a"}, {Name: "b", Active: true}}, "b", true},
		{"first active wins", []Script{{Name: "a", Active: true}, {Name: "b", Active: true}}, "a", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := activeScript(tt.in)
			if ok != tt.wantOK || got.Name != tt.wantName {
				t.Errorf("activeScript(%#v) = (%q,%v), want (%q,%v)", tt.in, got.Name, ok, tt.wantName, tt.wantOK)
			}
		})
	}
}

func TestNormalizeUser(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"simple", "user@example.com", "user@example.com", false},
		{"uppercase normalized", "User@Example.COM", "user@example.com", false},
		{"trims whitespace", "  user@example.com  ", "user@example.com", false},
		{"no domain", "user", "", true},
		{"empty", "", "", true},
		{"injection semicolon", "user;rm@example.com", "", true},
		{"injection space", "user name@example.com", "", true},
		{"injection newline", "user\n@example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeUser(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeUser(%q) = %q, want error", tt.in, got)
				}
				if !errors.Is(err, valid.ErrInvalid) {
					t.Errorf("normalizeUser(%q) error = %v, want wrapping valid.ErrInvalid", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeUser(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("normalizeUser(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCheckResult(t *testing.T) {
	sentinel := errors.New("boom")

	tests := []struct {
		name    string
		res     sys.Result
		runErr  error
		wantErr bool
		wantIs  error
	}{
		{
			name:    "success",
			res:     sys.Result{ExitCode: 0},
			runErr:  nil,
			wantErr: false,
		},
		{
			name:    "run error wrapped",
			res:     sys.Result{Stderr: []byte("stderr detail")},
			runErr:  sentinel,
			wantErr: true,
			wantIs:  sentinel,
		},
		{
			name:    "nonzero exit",
			res:     sys.Result{ExitCode: 75, Stderr: []byte("temp fail")},
			runErr:  nil,
			wantErr: true,
		},
		{
			name:    "nonzero exit falls back to stdout",
			res:     sys.Result{ExitCode: 64, Stdout: []byte("usage error")},
			runErr:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkResult(tt.res, tt.runErr, "op")
			if tt.wantErr != (err != nil) {
				t.Fatalf("checkResult() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("checkResult() error = %v, want wrapping %v", err, tt.wantIs)
			}
		})
	}
}

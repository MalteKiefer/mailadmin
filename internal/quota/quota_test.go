package quota

import (
	"errors"
	"testing"
)

func TestParseStorage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		out       string
		wantUsed  int64
		wantLimit int64
		wantErr   error
	}{
		{
			name:      "storage and message rows",
			out:       "Quota name\tType\tValue\tLimit\t%\nUser quota\tSTORAGE\t12345\t102400\t12\nUser quota\tMESSAGE\t42\t-\t0\n",
			wantUsed:  12345,
			wantLimit: 102400,
		},
		{
			name:      "space separated columns",
			out:       "User quota STORAGE 500 1000 50\n",
			wantUsed:  500,
			wantLimit: 1000,
		},
		{
			name:      "unlimited storage limit dash",
			out:       "User quota STORAGE 700 - 0\n",
			wantUsed:  700,
			wantLimit: 0,
		},
		{
			name:      "flat without trailing percent column",
			out:       "User quota STORAGE 800 1600\n",
			wantUsed:  800,
			wantLimit: 1600,
		},
		{
			name:      "quota name with spaces",
			out:       "My Big Quota STORAGE 10 100 10\n",
			wantUsed:  10,
			wantLimit: 100,
		},
		{
			name:    "message row only means no storage",
			out:     "User quota MESSAGE 5 50 10\n",
			wantErr: ErrParse,
		},
		{
			name:    "empty output",
			out:     "",
			wantErr: ErrParse,
		},
		{
			name:    "whitespace only output",
			out:     "   \n\t\n",
			wantErr: ErrParse,
		},
		{
			name:    "non-numeric value",
			out:     "User quota STORAGE abc 100 0\n",
			wantErr: ErrParse,
		},
		{
			name:    "non-numeric limit",
			out:     "User quota STORAGE 10 xyz 0\n",
			wantErr: ErrParse,
		},
		{
			name:    "header only",
			out:     "Quota name\tType\tValue\tLimit\t%\n",
			wantErr: ErrParse,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			used, limit, err := parseStorage([]byte(tt.out))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if used != tt.wantUsed || limit != tt.wantLimit {
				t.Fatalf("got used=%d limit=%d, want used=%d limit=%d",
					used, limit, tt.wantUsed, tt.wantLimit)
			}
		})
	}
}

func TestParseLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"1024", 1024, false},
		{"0", 0, false},
		{"-", 0, false},
		{"", 0, false},
		{"  512 ", 512, false},
		{"nan", 0, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseLimit(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPercent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		used  int64
		limit int64
		want  int
	}{
		{"half", 50, 100, 50},
		{"exact full", 100, 100, 100},
		{"over limit clamps", 250, 100, 100},
		{"zero limit unlimited", 500, 0, 0},
		{"negative limit", 500, -1, 0},
		{"zero used", 0, 100, 0},
		{"rounds down", 1, 3, 33},
		{"empty everything", 0, 0, 0},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := percent(tt.used, tt.limit); got != tt.want {
				t.Fatalf("percent(%d,%d) = %d, want %d",
					tt.used, tt.limit, got, tt.want)
			}
		})
	}
}

func TestNormalizeAddress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"User@Example.COM", "user@example.com", false},
		{"  jane@sub.example.org  ", "jane@sub.example.org", false},
		{"a.b+tag@example.com", "a.b+tag@example.com", false},
		{"no-at-sign", "", true},
		{"two@@example.com", "", true},
		{"user@", "", true},
		{"@example.com", "", true},
		{"user@example", "", true},
		{"", "", true},
		{"user@ex ample.com", "", true},
		{"us;rm -rf@example.com", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeAddress(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeAddress(%q) err = %v, wantErr = %v", tt.in, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("normalizeAddress(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

package cli

import "testing"

func TestDaneSubname(t *testing.T) {
	cases := []struct {
		mailHost, domain, want string
		wantErr                bool
	}{
		{"mail.example.com", "example.com", "_25._tcp.mail", false},
		{"example.com", "example.com", "_25._tcp", false},
		{"mx1.mail.example.com", "example.com", "_25._tcp.mx1.mail", false},
		{"MAIL.Example.COM.", "example.com", "_25._tcp.mail", false},
		{"mail.other.net", "example.com", "", true},
		{"", "example.com", "", true},
	}
	for _, c := range cases {
		got, err := daneSubname(c.mailHost, c.domain)
		if c.wantErr {
			if err == nil {
				t.Errorf("daneSubname(%q,%q) = %q, want error", c.mailHost, c.domain, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("daneSubname(%q,%q) error: %v", c.mailHost, c.domain, err)
			continue
		}
		if got != c.want {
			t.Errorf("daneSubname(%q,%q) = %q, want %q", c.mailHost, c.domain, got, c.want)
		}
	}
}

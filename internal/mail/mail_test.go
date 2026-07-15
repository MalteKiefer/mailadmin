package mail

import (
	"errors"
	"strings"
	"testing"

	"mailadmin/internal/dnsprovider"
)

// index maps a record set by "TYPE NAME" for easy lookup in assertions.
func index(recs []dnsprovider.Record) map[string]dnsprovider.Record {
	out := make(map[string]dnsprovider.Record, len(recs))
	for _, r := range recs {
		out[r.Type+" "+r.Name] = r
	}
	return out
}

// realKey is a verbatim rspamadm dkim_keygen public-key file (kiefer-networks).
const realKey = `mail2026._domainkey IN TXT ( "v=DKIM1; k=rsa; "
	"p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAutMr4fhaKrvoRdnSkQ50wUvakIxhyJEydgP3bXfmuCJ0bcGuHJ3EZQZkDcUV4g2t04rF7x+XdE1cTDAVm7hCH1sTsOxKm9CW039ApesPZNNMVr5kdECfBSFdY/Q264UPForgcGhseB4o7FVv15N2LF01FglRI5JQSvBQ+gQCOYoVOTtfxxE/C5gAu69fycqEyYQsJTx2GOCaa9jIi"
	"ka1DYjr5PHeJn/8UVOuairQCMX2oOkfPGsZQgOzaTv+ep81TFrV0VhphU55CE9taiovu7Gsu1kDQIxHkeiyKVJMBxK+WXywdV7q2qJhVhBOHM9vo/alBsSoIN+5DGg0BY+6lwIDAQAB"
) ; `

func TestParseDKIMPublic(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{
			name: "rspamadm two-segment file",
			in:   realKey,
			want: "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAutMr4fhaKrvoRdnSkQ50wUvakIxhyJEydgP3bXfmuCJ0bcGuHJ3EZQZkDcUV4g2t04rF7x+XdE1cTDAVm7hCH1sTsOxKm9CW039ApesPZNNMVr5kdECfBSFdY/Q264UPForgcGhseB4o7FVv15N2LF01FglRI5JQSvBQ+gQCOYoVOTtfxxE/C5gAu69fycqEyYQsJTx2GOCaa9jIika1DYjr5PHeJn/8UVOuairQCMX2oOkfPGsZQgOzaTv+ep81TFrV0VhphU55CE9taiovu7Gsu1kDQIxHkeiyKVJMBxK+WXywdV7q2qJhVhBOHM9vo/alBsSoIN+5DGg0BY+6lwIDAQAB",
		},
		{
			name: "single quoted segment",
			in:   `sel._domainkey IN TXT ( "v=DKIM1; k=rsa; p=ABC123" ) ;`,
			want: "v=DKIM1; k=rsa; p=ABC123",
		},
		{
			name: "plain unquoted line",
			in:   "v=DKIM1; k=rsa; p=ABC123",
			want: "v=DKIM1; k=rsa; p=ABC123",
		},
		{
			name: "plain unquoted line with surrounding noise",
			in:   "# comment\nv=DKIM1; k=rsa; p=XYZ\n",
			want: "v=DKIM1; k=rsa; p=XYZ",
		},
		{
			name:    "empty file",
			in:      "",
			wantErr: errMissingDKIMPrefix,
		},
		{
			name:    "whitespace only",
			in:      "   \n\t\n",
			wantErr: errMissingDKIMPrefix,
		},
		{
			name:    "quoted but wrong prefix",
			in:      `sel IN TXT ( "k=rsa; p=ABC" ) ;`,
			wantErr: errMissingDKIMPrefix,
		},
		{
			name:    "unquoted wrong prefix",
			in:      "not a dkim record at all",
			wantErr: errMissingDKIMPrefix,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDKIMPublic(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJoinQuoted(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no quotes", "abc def", ""},
		{"one segment", `"hello"`, "hello"},
		{"two segments", `"foo " "bar"`, "foo bar"},
		{"segments across lines", "\"a\"\n\t\"b\"\n\"c\"", "abc"},
		{"empty quotes", `"" "x"`, "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := joinQuoted(tt.in); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFirstDKIMLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"direct", "v=DKIM1; p=x", "v=DKIM1; p=x"},
		{"case insensitive", "V=dkim1; p=x", "V=dkim1; p=x"},
		{"skips leading lines", "junk\n\nv=DKIM1; p=x\ntail", "v=DKIM1; p=x"},
		{"none", "no key here", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstDKIMLine(tt.in); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestManagerPaths(t *testing.T) {
	m := New(nil, "/var/lib/rspamd/dkim", "mail.example.com", "192.0.2.1", "2001:db8::1")
	priv, pub := m.paths("example.com", "mail2026")
	if priv != "/var/lib/rspamd/dkim/example.com.mail2026.key" {
		t.Fatalf("priv = %q", priv)
	}
	if pub != "/var/lib/rspamd/dkim/example.com.mail2026.key.pub" {
		t.Fatalf("pub = %q", pub)
	}
}

func TestDesiredRecords(t *testing.T) {
	m := New(nil, "/var/lib/rspamd/dkim", "mail.example.com", "192.0.2.1", "2001:db8::1")

	// Without MTA-STS: no _mta-sts / mta-sts host records.
	got := m.DesiredRecords("example.com", "mail2026", "v=DKIM1; k=rsa; p=ABC", false)
	byName := index(got)
	if _, ok := byName["TXT _mta-sts"]; ok {
		t.Fatalf("did not expect _mta-sts record when withMTASTS=false")
	}
	dkim, ok := byName["TXT mail2026._domainkey"]
	if !ok {
		t.Fatalf("missing DKIM record; got %+v", got)
	}
	if dkim.Content != "v=DKIM1; k=rsa; p=ABC" {
		t.Fatalf("DKIM content = %q", dkim.Content)
	}
	mx, ok := byName["MX @"]
	if !ok || mx.Content != "mail.example.com." || mx.Prio != 10 {
		t.Fatalf("MX record wrong: %+v", mx)
	}
	if srv, ok := byName["SRV _imaps._tcp"]; !ok || srv.Port != 993 || srv.Content != "mail.example.com." {
		t.Fatalf("imaps SRV wrong: %+v ok=%v", srv, ok)
	}
	if cn, ok := byName["CNAME autoconfig"]; !ok || cn.Content != "mail.example.com." {
		t.Fatalf("autoconfig CNAME wrong: %+v ok=%v", cn, ok)
	}
	// Host A/AAAA emitted because mail.example.com is inside example.com.
	if a, ok := byName["A mail"]; !ok || a.Content != "192.0.2.1" {
		t.Fatalf("host A record wrong: %+v ok=%v", a, ok)
	}
	if aaaa, ok := byName["AAAA mail"]; !ok || aaaa.Content != "2001:db8::1" {
		t.Fatalf("host AAAA record wrong: %+v ok=%v", aaaa, ok)
	}
	for _, r := range got {
		if r.TTL != dkimTTL {
			t.Fatalf("record %s %s TTL = %d, want %d", r.Type, r.Name, r.TTL, dkimTTL)
		}
	}

	// With MTA-STS: _mta-sts + mta-sts host records appear.
	got = m.DesiredRecords("example.com", "mail2026", "v=DKIM1; k=rsa; p=ABC", true)
	byName = index(got)
	sts, ok := byName["TXT _mta-sts"]
	if !ok || !strings.HasPrefix(sts.Content, "v=STSv1; id=") {
		t.Fatalf("_mta-sts record wrong: %+v ok=%v", sts, ok)
	}
	if _, ok := byName["A mta-sts"]; !ok {
		t.Fatalf("missing mta-sts host A record")
	}
}

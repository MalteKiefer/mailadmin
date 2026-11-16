package dnsprovider

import "testing"

func TestSubLabel(t *testing.T) {
	cases := []struct {
		fqdn, domain, want string
		ok                 bool
	}{
		{"apple.kiefer-networks.de", "kiefer-networks.de", "apple", true},
		{"APPLE.Kiefer-Networks.de.", "kiefer-networks.de", "apple", true},
		{"apple.pinlo.me", "kiefer-networks.de", "", false},
		{"kiefer-networks.de", "kiefer-networks.de", "", false},
		{"a.b.kiefer-networks.de", "kiefer-networks.de", "", false},
		{"", "kiefer-networks.de", "", false},
	}
	for _, c := range cases {
		got, ok := subLabel(c.fqdn, c.domain)
		if got != c.want || ok != c.ok {
			t.Errorf("subLabel(%q,%q) = %q,%v want %q,%v", c.fqdn, c.domain, got, ok, c.want, c.ok)
		}
	}
}

func TestDesiredRecordsIncludeAppleHostOnlyWhenSet(t *testing.T) {
	base := MailRecordOpts{MailHost: "mail.kiefer-networks.de", IPv4: "192.0.2.10", IPv6: "2001:db8::10", Selector: "mail2026", DKIMValue: "v=DKIM1; k=rsa; p=x", TTL: 3600}
	has := func(recs []Record, typ, name string) bool {
		for _, r := range recs {
			if r.Type == typ && r.Name == name {
				return true
			}
		}
		return false
	}
	off := DesiredMailRecords("kiefer-networks.de", base)
	if has(off, "A", "apple") || has(off, "AAAA", "apple") {
		t.Fatal("apple records present while the form is off")
	}
	on := base
	on.AppleFQDN = "apple.kiefer-networks.de"
	recs := DesiredMailRecords("kiefer-networks.de", on)
	if !has(recs, "A", "apple") || !has(recs, "AAAA", "apple") {
		t.Fatal("apple A/AAAA missing while the form is on")
	}
	other := DesiredMailRecords("pinlo.me", on)
	if has(other, "A", "apple") {
		t.Fatal("apple record created in a domain that does not own the form host")
	}
}

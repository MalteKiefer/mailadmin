package valid

import "testing"

// These fuzz targets cover the three validators that sit directly between
// untrusted CLI input and either an exec argv (CIDR feeds cscli/nft calls) or
// a SQL parameter / DNS query (Domain, Address). The invariant under fuzzing
// is simple and deliberately weak — no panic, and on success the returned
// value is idempotent (re-validating it succeeds and is unchanged) — because
// the interesting bugs here are memory-safety/DoS issues (a crafted string
// causing the regexp engine or net.ParseIP/ParseCIDR to hang or panic), not
// business-logic correctness (that's covered by table-driven tests elsewhere
// once those exist).

func FuzzDomain(f *testing.F) {
	for _, seed := range []string{
		"example.com",
		"EXAMPLE.COM.",
		"  example.com  ",
		"",
		"-bad-.com",
		"a..b",
		"xn--80akhbyknj4f",
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := Domain(s)
		if err != nil {
			return
		}
		again, err2 := Domain(got)
		if err2 != nil {
			t.Fatalf("Domain(%q) = %q, but Domain(%q) errored: %v", s, got, got, err2)
		}
		if again != got {
			t.Fatalf("Domain not idempotent: Domain(%q)=%q, Domain(%q)=%q", s, got, got, again)
		}
	})
}

func FuzzAddress(f *testing.F) {
	for _, seed := range []string{
		"user@example.com",
		"USER@EXAMPLE.COM",
		"a.b+c-d_e@sub.example.com",
		"",
		"@example.com",
		"user@",
		"user@@example.com",
		"us;rm -rf@example.com",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		local, domain, err := Address(s)
		if err != nil {
			return
		}
		if local == "" || domain == "" {
			t.Fatalf("Address(%q) returned empty part: local=%q domain=%q", s, local, domain)
		}
		again, _, err2 := Address(local + "@" + domain)
		if err2 != nil {
			t.Fatalf("Address(%q)=%q@%q, but re-validating %q@%q errored: %v", s, local, domain, local, domain, err2)
		}
		if again != local {
			t.Fatalf("Address local-part not idempotent: %q vs %q", local, again)
		}
	})
}

func FuzzCIDR(f *testing.F) {
	for _, seed := range []string{
		"192.0.2.1",
		"192.0.2.0/24",
		"::1",
		"2001:db8::/32",
		"",
		"not-an-ip",
		"192.0.2.1/33",
		"999.999.999.999",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := CIDR(s)
		if err != nil {
			return
		}
		if _, err2 := CIDR(got); err2 != nil {
			t.Fatalf("CIDR(%q) = %q, but CIDR(%q) errored: %v", s, got, got, err2)
		}
	})
}

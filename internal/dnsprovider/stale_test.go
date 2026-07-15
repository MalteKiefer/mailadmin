package dnsprovider

import (
	"strings"
	"testing"
)

func TestStale(t *testing.T) {
	live := []Record{
		{ID: "1", Type: "MX", Name: "@", Content: "old.mx."},
		{ID: "2", Type: "A", Name: "@", Content: "1.2.3.4"},
		{ID: "3", Type: "CNAME", Name: "dkim._domainkey", Content: "x.simplelogin.co."},
		{ID: "4", Type: "AAAA", Name: "www", Content: "::1"},
	}
	desired := []Record{{Type: "MX", Name: "@", Content: "new.mx.", Prio: 10}}

	all := Stale(live, desired, false)
	if len(all) != 3 { // A@, CNAME, AAAA www — MX matched by key
		t.Fatalf("want 3 stale, got %d: %+v", len(all), all)
	}
	web := Stale(live, desired, true)
	// protectApexWeb keeps A@ and AAAA www; only the CNAME remains stale.
	if len(web) != 1 || web[0].Type != "CNAME" {
		t.Fatalf("want 1 stale (CNAME) with web protected, got %+v", web)
	}
}

func TestPlanCurrent(t *testing.T) {
	// Same TXT scheme (SPF) → same managed slot → edit old value to new.
	live := []Record{{ID: "9", Type: "TXT", Name: "@", Content: "v=spf1 include:old ~all"}}
	desired := []Record{{Type: "TXT", Name: "@", Content: "v=spf1 mx -all"}}
	plan := Plan(live, desired)
	if len(plan) != 1 || plan[0].Op != OpEdit {
		t.Fatalf("want 1 edit, got %+v", plan)
	}
	if plan[0].Current == nil || plan[0].Current.Content != "v=spf1 include:old ~all" {
		t.Fatalf("edit change must carry current (old) content, got %+v", plan[0].Current)
	}
	if plan[0].Record.ID != "9" {
		t.Fatalf("edit must inherit live ID for the update, got %q", plan[0].Record.ID)
	}
}

// TestPlanMultiValue is the bulletproof case: two live MX plus an unrelated
// verification TXT at the apex. The mail set wants one MX and one SPF and must
// edit one MX to the wanted host, DELETE the surplus MX, add SPF, and leave the
// foreign verification TXT untouched (it is Stale, not in Plan).
func TestPlanMultiValue(t *testing.T) {
	live := []Record{
		{ID: "1", Type: "MX", Name: "@", Content: "mx1.simplelogin.co.", Prio: 10},
		{ID: "2", Type: "MX", Name: "@", Content: "mx2.simplelogin.co.", Prio: 20},
		{ID: "3", Type: "TXT", Name: "@", Content: "verify=abc123"},
	}
	desired := []Record{
		{Type: "MX", Name: "@", Content: "mail.kiefer-networks.de", Prio: 10},
		{Type: "TXT", Name: "@", Content: "v=spf1 mx -all"},
	}
	var edit, del, add int
	for _, c := range Plan(live, desired) {
		switch c.Op {
		case OpEdit:
			edit++
		case OpDelete:
			del++
			if c.Current == nil || c.Current.Type != "MX" {
				t.Fatalf("delete must target the surplus MX, got %+v", c.Current)
			}
		case OpAdd:
			add++
		}
	}
	if edit != 1 || del != 1 || add != 1 {
		t.Fatalf("want edit=1 del=1 add=1, got edit=%d del=%d add=%d", edit, del, add)
	}
	st := Stale(live, desired, false)
	if len(st) != 1 || st[0].Content != "verify=abc123" {
		t.Fatalf("verification TXT must be stale + untouched, got %+v", st)
	}
}

// TestDesiredIncludesAutodiscover verifies the mail set now advertises client
// autodiscovery: SRV for imaps/submissions/autodiscover plus autoconfig and
// autodiscover host records.
func TestDesiredIncludesAutodiscover(t *testing.T) {
	recs := DesiredMailRecords("p37.nexus", MailRecordOpts{
		MailHost: "mail.kiefer-networks.de", IPv4: "203.0.113.1", IPv6: "2001:db8::1",
		Selector: "mail2026", DKIMValue: "v=DKIM1; k=rsa; p=AAAA",
	})
	want := map[string]bool{
		"SRV\x00_imaps._tcp":        false,
		"SRV\x00_submissions._tcp":  false,
		"SRV\x00_autodiscover._tcp": false,
		"CNAME\x00autoconfig":       false,
		"CNAME\x00autodiscover":     false,
	}
	for _, r := range recs {
		key := strings.ToUpper(r.Type) + "\x00" + r.Name
		if _, ok := want[key]; ok {
			want[key] = true
		}
		if strings.EqualFold(r.Type, "SRV") && r.Name == "_imaps._tcp" {
			if r.Port != 993 || r.Content != "mail.kiefer-networks.de." {
				t.Fatalf("imaps SRV wrong: %+v", r)
			}
		}
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("desired set missing %q", k)
		}
	}
}

// TestSRVReconcile confirms an SRV whose port/target drift is detected as edit.
func TestSRVReconcile(t *testing.T) {
	live := []Record{{ID: "5", Type: "SRV", Name: "_imaps._tcp", Content: "old.host", Prio: 0, Weight: 1, Port: 143}}
	desired := []Record{{Type: "SRV", Name: "_imaps._tcp", Content: "mail.host", Prio: 0, Weight: 1, Port: 993}}
	plan := Plan(live, desired)
	if len(plan) != 1 || plan[0].Op != OpEdit {
		t.Fatalf("want 1 edit for SRV drift, got %+v", plan)
	}
}

package webserver

import (
	"strings"
	"testing"
)

func TestBlock(t *testing.T) {
	m := New(nil, "", "", "", "")
	out := m.Block([]string{"p37.nexus", "kiefer-networks.de", "p37.nexus"}) // dupe
	for _, want := range []string{
		"autoconfig.kiefer-networks.de, autoconfig.p37.nexus {",
		"autodiscover.kiefer-networks.de, autodiscover.p37.nexus {",
		"root * /srv/caddy/autoconfig",
		"rewrite @ms /autodiscover.xml",
		"method GET",
		"Managed by mailadmin",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("block missing %q\n---\n%s", want, out)
		}
	}
	// sorted + deduped: kiefer before p37, p37 only once.
	if strings.Count(out, "autoconfig.p37.nexus") != 1 {
		t.Errorf("p37 not deduped:\n%s", out)
	}
}

func TestBlockEmpty(t *testing.T) {
	if New(nil, "", "", "", "").Block(nil) != "" {
		t.Fatal("empty domain list must yield empty block")
	}
}

func TestMTASTSBlock(t *testing.T) {
	m := New(nil, "", "", "", "")
	out := m.MTASTSBlock([]string{"p37.nexus", "kiefer-networks.de", "p37.nexus"}) // dupe
	for _, want := range []string{
		"mta-sts.kiefer-networks.de, mta-sts.p37.nexus {",
		"root * /srv/caddy/mta-sts",
		"@policy path /.well-known/mta-sts.txt",
		"header @policy Content-Type text/plain",
		"file_server",
		"Managed by mailadmin",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("mta-sts block missing %q\n---\n%s", want, out)
		}
	}
	// sorted + deduped: kiefer before p37, p37 only once.
	if strings.Count(out, "mta-sts.p37.nexus") != 1 {
		t.Errorf("p37 not deduped:\n%s", out)
	}
}

func TestMTASTSBlockEmpty(t *testing.T) {
	if New(nil, "", "", "", "").MTASTSBlock(nil) != "" {
		t.Fatal("empty domain list must yield empty mta-sts block")
	}
}

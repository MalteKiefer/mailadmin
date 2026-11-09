package webserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMTASTSPolicyContent(t *testing.T) {
	got := MTASTSPolicy("mail.example.com")
	for _, want := range []string{"version: STSv1", "mode: testing", "mx: mail.example.com", "max_age: 604800"} {
		if !strings.Contains(got, want) {
			t.Fatalf("policy missing %q:\n%s", want, got)
		}
	}
}

func TestWriteMTASTSPolicyWritesServedFile(t *testing.T) {
	root := t.TempDir()
	m := &Manager{mtaStsRoot: root}
	if err := m.WriteMTASTSPolicy("mail.example.com"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, ".well-known", "mta-sts.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != MTASTSPolicy("mail.example.com") {
		t.Fatalf("policy file content mismatch:\n%s", data)
	}
}

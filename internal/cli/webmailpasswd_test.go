package cli

import (
	"strings"
	"testing"
)

func TestReadPasswordPairKeepsSpaces(t *testing.T) {
	cur, next, err := readPasswordPair(strings.NewReader("old pass\nnew pass\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cur != "old pass" || next != "new pass" {
		t.Fatalf("got %q, %q", cur, next)
	}
}

func TestReadPasswordPairRefusesMissingOrEmptyLines(t *testing.T) {
	for name, in := range map[string]string{
		"one line only": "old\n",
		"empty current": "\nnew\n",
		"empty new":     "old\n\n",
		"nothing":       "",
	} {
		if _, _, err := readPasswordPair(strings.NewReader(in)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestReadPasswordPairAcceptsLastLineWithoutNewline(t *testing.T) {
	cur, next, err := readPasswordPair(strings.NewReader("old\nnew"))
	if err != nil {
		t.Fatal(err)
	}
	if cur != "old" || next != "new" {
		t.Fatalf("got %q, %q", cur, next)
	}
}

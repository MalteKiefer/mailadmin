package postfixq

import "testing"

func TestPostsuperChanged(t *testing.T) {
	for out, want := range map[string]bool{
		"postsuper: Deleted: 1 message\n":          true,
		"postsuper: Placed on hold: 3 messages\n":  true,
		"postsuper: Released from hold: 1 message": true,
		"":                                 false,
		"postsuper: Deleted: 0 messages\n": false,
	} {
		if got := postsuperChanged([]byte(out)); got != want {
			t.Errorf("postsuperChanged(%q) = %v, want %v", out, got, want)
		}
	}
}

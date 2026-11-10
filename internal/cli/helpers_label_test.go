package cli

import "testing"

func TestCheckNewLabelMatchesDovecotLogins(t *testing.T) {
	for label, ok := range map[string]bool{
		"iphone": true, "work-laptop_2.0": true,
		"iPhone": false, "Work Laptop": false, "a+b": false, "a@b": false, "ümlaut": false, "-x": false,
	} {
		if err := checkNewLabel(label); (err == nil) != ok {
			t.Errorf("checkNewLabel(%q) = %v, want ok=%v", label, err, ok)
		}
	}
}

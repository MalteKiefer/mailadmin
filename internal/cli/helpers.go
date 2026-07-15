package cli

import (
	"fmt"
	"strings"
	"unicode"
)

// boolYesNo renders a boolean as a compact yes/no cell for table output.
func boolYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// maxLabelLen bounds an application-password label length.
const maxLabelLen = 64

// validLabel validates and trims an application-password label. Labels are
// user-facing free text but must stay printable and single-line so they cannot
// smuggle control characters into audit logs or terminal output. The label is a
// SQL parameter (never interpolated), so this guards presentation and log
// integrity rather than injection.
func validLabel(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("label must not be empty")
	}
	if len(s) > maxLabelLen {
		return "", fmt.Errorf("label too long (max %d bytes)", maxLabelLen)
	}
	for _, r := range s {
		if r == unicode.ReplacementChar || (unicode.IsControl(r)) {
			return "", fmt.Errorf("label contains control characters")
		}
	}
	return s, nil
}

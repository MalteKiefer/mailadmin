package config

import (
	"strings"
)

// FormatTOML rewrites a TOML document into one layout: no indentation, "key = value"
// with single spaces, one blank line before each table header, no runs of blank
// lines, no trailing spaces. Comments and values keep their text. Multi-line
// arrays and strings are copied as they are.
func FormatTOML(text string) string {
	var out []string
	inMulti := false // inside a multi-line string or array, copied verbatim
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if inMulti {
			out = append(out, line)
			if closesMulti(line) {
				inMulti = false
			}
			continue
		}
		t := strings.TrimSpace(line)
		switch {
		case t == "":
			if len(out) > 0 && out[len(out)-1] != "" {
				out = append(out, "")
			}
			continue
		case strings.HasPrefix(t, "#"):
			out = append(out, t)
		case strings.HasPrefix(t, "["):
			if len(out) > 0 && out[len(out)-1] != "" {
				out = append(out, "")
			}
			out = append(out, t)
		default:
			k, v, ok := splitKV(t)
			if !ok {
				out = append(out, t)
				continue
			}
			out = append(out, k+" = "+v)
			if opensMulti(v) {
				inMulti = true
			}
		}
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return strings.Join(out, "\n") + "\n"
}

// splitKV splits "key = value" at the first "=" outside a quoted key.
func splitKV(t string) (key, value string, ok bool) {
	i := strings.Index(t, "=")
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(t[:i])
	value = strings.TrimSpace(t[i+1:])
	return key, value, key != "" && value != ""
}

// opensMulti reports whether a value starts a multi-line array or string.
func opensMulti(v string) bool {
	if strings.HasPrefix(v, `"""`) || strings.HasPrefix(v, `'''`) {
		return !strings.HasSuffix(v, `"""`) || len(v) == 3
	}
	return strings.HasPrefix(v, "[") && !strings.Contains(v, "]")
}

// closesMulti reports whether a verbatim line ends a multi-line value.
func closesMulti(line string) bool {
	return strings.Contains(line, `"""`) || strings.Contains(line, `'''`) || strings.Contains(line, "]")
}

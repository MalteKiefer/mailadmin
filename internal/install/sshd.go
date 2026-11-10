package install

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SSHPorts returns the ports sshd listens on, read from sshd_config and its
// drop-ins. Port lines and the port of ListenAddress entries both count. With
// neither, sshd listens on 22.
func SSHPorts() []int {
	files := []string{"/etc/ssh/sshd_config"}
	if more, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		files = append(files, more...)
	}
	var config []string
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- fixed sshd config paths
		if err != nil {
			continue
		}
		config = append(config, string(data))
	}
	return parseSSHPorts(strings.Join(config, "\n"))
}

func parseSSHPorts(config string) []int {
	seen := map[int]bool{}
	var ports []int
	add := func(n int) {
		if !seen[n] {
			seen[n] = true
			ports = append(ports, n)
		}
	}
	for _, line := range strings.Split(config, "\n") {
		// sshd ends a line at a "#" that starts a word (Port 2222 # moved).
		if i := strings.Index(line, "#"); i == 0 || (i > 0 && (line[i-1] == ' ' || line[i-1] == '\t')) {
			line = line[:i]
		}
		// sshd accepts "Keyword value" and "Keyword=value", with optional blanks around "=".
		// ListenAddress may carry a trailing "rdomain name".
		fields := strings.Fields(strings.Replace(line, "=", " ", 1))
		if len(fields) < 2 {
			continue
		}
		switch {
		case strings.EqualFold(fields[0], "Port"):
			if n, ok := validPort(fields[1]); ok {
				add(n)
			}
		case strings.EqualFold(fields[0], "ListenAddress"):
			if n, ok := listenPort(fields[1]); ok {
				add(n)
			}
		}
	}
	if len(ports) == 0 {
		return []int{22}
	}
	return ports
}

// listenPort returns the port of a ListenAddress value such as 0.0.0.0:2222 or
// [::]:2222. A bare address without a port yields nothing.
func listenPort(v string) (int, bool) {
	if strings.Count(v, ":") > 1 && !strings.HasPrefix(v, "[") {
		return 0, false // bare IPv6 literal, no port
	}
	i := strings.LastIndex(v, ":")
	if i < 0 {
		return 0, false
	}
	return validPort(v[i+1:])
}

func validPort(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && n > 0 && n < 65536
}

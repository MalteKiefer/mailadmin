package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DistroPackages come from the distribution archive.
func DistroPackages() []string {
	return []string{
		"ca-certificates", "curl", "gnupg",
		"postfix", "postfix-pgsql",
		"dovecot-core", "dovecot-imapd", "dovecot-lmtpd", "dovecot-pgsql",
		"dovecot-sieve", "dovecot-managesieved",
		"rspamd",
		"nftables", "iproute2", "openssl",
	}
}

// VendorPackages come from the repositories added by AddRepos.
func VendorPackages() []string {
	return []string{"postgresql", "caddy"}
}

// PostfixPreseed answers the postfix debconf questions so apt never prompts.
// "Internet Site" makes postfix deliver mail itself, which is what a mail host needs.
func PostfixPreseed(hostname string) []byte {
	return []byte(fmt.Sprintf(
		"postfix postfix/main_mailer_type select Internet Site\npostfix postfix/mailname string %s\n",
		hostname))
}

// aptEnv runs apt-get without prompts.
func aptEnv(args ...string) []string {
	return append([]string{"env", "DEBIAN_FRONTEND=noninteractive", trustedBin("apt-get"), "-y", "--no-install-recommends"}, args...)
}

// AptUpdate refreshes the package index.
func AptUpdate(ctx context.Context, x Exec) error {
	if _, err := x.Run(ctx, nil, "env", "DEBIAN_FRONTEND=noninteractive", trustedBin("apt-get"), "update"); err != nil {
		return fmt.Errorf("apt-get update: %w", err)
	}
	return nil
}

// PolicyRCPath is Debian's policy hook that decides whether package
// maintainer scripts may start a service. install denies starts while it runs.
// It is a variable so tests can point it at a temp file.
var PolicyRCPath = "/usr/sbin/policy-rc.d"

// policyMarker is the second line of a policy-rc.d that install wrote. Only a file
// with this line is ours to replace and remove.
const policyMarker = "# managed by mailadmin install"

// policyDenied is the exit code a policy-rc.d uses to refuse a service start.
const policyDenied = 101

// AptInstall installs packages. Postfix debconf answers are preseeded first.
// Services are not started by the maintainer scripts: postfix and dovecot would
// otherwise listen on the network with distribution defaults before mailadmin
// has configured them. install starts what it needs explicitly later.
func AptInstall(ctx context.Context, x Exec, pkgs []string, hostname string) error {
	// debconf-set-selections ships in debconf-utils, which a minimal image may lack.
	if _, err := x.Run(ctx, nil, aptEnv("install", "debconf-utils")...); err != nil {
		return fmt.Errorf("install debconf-utils: %w", err)
	}
	if _, err := x.Run(ctx, PostfixPreseed(hostname), "debconf-set-selections"); err != nil {
		return fmt.Errorf("preseed postfix: %w", err)
	}
	created, err := denyServiceStarts(ctx, x)
	if err != nil {
		return err
	}
	if created {
		defer func() { _ = os.Remove(PolicyRCPath) }()
	}
	if _, err := x.Run(ctx, nil, aptEnv(append([]string{"install"}, pkgs...)...)...); err != nil {
		return fmt.Errorf("apt-get install: %w", err)
	}
	return nil
}

// denyServiceStarts installs a policy-rc.d that refuses service starts. A policy
// file without the mailadmin marker belongs to someone else and is left alone.
// It reports whether this run owns the file, so only install removes it again.
func denyServiceStarts(ctx context.Context, x Exec) (bool, error) {
	data, err := os.ReadFile(PolicyRCPath) // #nosec G304 -- fixed apt hook path
	switch {
	case err == nil && !strings.Contains(string(data), policyMarker):
		// Not ours, so it is left alone. Probe it instead: apt must not start daemons
		// under a policy that allows starts.
		res, _ := x.Run(ctx, nil, PolicyRCPath, "mailadmin-probe", "start")
		if res.ExitCode != policyDenied {
			return false, fmt.Errorf("%s exists and does not deny service starts (exit %d): remove it or make it exit %d", PolicyRCPath, res.ExitCode, policyDenied)
		}
		return false, nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return false, fmt.Errorf("read %s: %w", PolicyRCPath, err)
	}
	policy := "#!/bin/sh\n" + policyMarker + "\nexit 101\n"
	if err := os.WriteFile(PolicyRCPath, []byte(policy), 0o755); err != nil { // #nosec G306 -- must be executable for apt
		return false, fmt.Errorf("write %s: %w", PolicyRCPath, err)
	}
	return true, nil
}

// PackageInstalled reports whether dpkg has pkg installed. The status is read
// from its last field, so "hold ok installed" counts and "install ok half-configured"
// does not.
func PackageInstalled(ctx context.Context, x Exec, pkg string) bool {
	res, err := x.Run(ctx, nil, "dpkg-query", "-W", "-f=${Status}", pkg)
	if err != nil {
		return false
	}
	return statusInstalled(string(res.Stdout))
}

// statusInstalled reports whether a dpkg Status string ends in "installed".
func statusInstalled(status string) bool {
	fields := strings.Fields(status)
	return len(fields) > 0 && fields[len(fields)-1] == "installed"
}

// Conflicts lists mail-stack state already present under root or in dpkg.
// install refuses to touch such a host unless --adopt is given.
func Conflicts(ctx context.Context, x Exec, root string) []string {
	var out []string
	for _, p := range []string{
		"etc/postfix/main.cf",
		"etc/dovecot/dovecot.conf",
		"etc/caddy/Caddyfile",
		"etc/mailadmin/config.toml",
		"var/lib/postgresql",
	} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			out = append(out, "/"+p)
		}
	}
	for _, pkg := range []string{"postfix", "dovecot-core", "rspamd", "caddy", "postgresql"} {
		if PackageInstalled(ctx, x, pkg) {
			out = append(out, "package "+pkg)
		}
	}
	return out
}

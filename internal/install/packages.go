package install

import (
	"context"
	"fmt"
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
	return append([]string{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "--no-install-recommends"}, args...)
}

// AptUpdate refreshes the package index.
func AptUpdate(ctx context.Context, x Exec) error {
	if _, err := x.Run(ctx, nil, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"); err != nil {
		return fmt.Errorf("apt-get update: %w", err)
	}
	return nil
}

// PolicyRCPath is Debian's policy hook that decides whether package
// maintainer scripts may start a service. install denies starts while it runs.
const PolicyRCPath = "/usr/sbin/policy-rc.d"

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
	created, err := denyServiceStarts()
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

// denyServiceStarts installs a policy-rc.d that refuses service starts. It
// reports whether it created the file, so only install removes it again.
func denyServiceStarts() (bool, error) {
	if _, err := os.Stat(PolicyRCPath); err == nil {
		return false, nil
	}
	if err := os.WriteFile(PolicyRCPath, []byte("#!/bin/sh\nexit 101\n"), 0o755); err != nil { // #nosec G306 -- must be executable for apt
		return false, fmt.Errorf("write %s: %w", PolicyRCPath, err)
	}
	return true, nil
}

// PackageInstalled reports whether dpkg has pkg installed.
func PackageInstalled(ctx context.Context, x Exec, pkg string) bool {
	res, err := x.Run(ctx, nil, "dpkg-query", "-W", "-f=${Status}", pkg)
	return err == nil && strings.Contains(string(res.Stdout), "install ok installed")
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

package install

import (
	"context"
	"fmt"

	"mailadmin/internal/applemobile"
	"mailadmin/internal/config"
)

const (
	// AppleUser runs the profile form. It has no login shell and no home.
	AppleUser = "appleform"
	// AppleUnit is the systemd unit of the profile form.
	AppleUnit = "mailadmin-apple.service"
	// AppleUnitPath is where the unit is written.
	AppleUnitPath = "/etc/systemd/system/" + AppleUnit
	// AppleCaddy is the Caddy vhost of the form.
	AppleCaddy = CaddyIncludeDir + "/apple.caddy"
	// AppleDomainsPath is the allow-list of active mail domains the form reads. It sits in
	// the root-owned config directory, because /var/lib/mailadmin is private to mailadmin.
	AppleDomainsPath = "/etc/mailadmin/apple-domains"
)

// AppleUnitFile renders the systemd unit. The form service reads the allow-list and
// needs no database and no root.
func AppleUnitFile(a config.Apple, hostname string) string {
	return "# Managed by mailadmin install.\n[Unit]\nDescription=mailadmin Apple profile form\nAfter=network-online.target\nWants=network-online.target\n\n" +
		"[Service]\nUser=" + AppleUser + "\nGroup=" + AppleUser + "\n" +
		"ExecStart=/usr/local/sbin/mailadmin apple-serve --listen " + a.Listen + " --host " + hostname + " --domains-file " + AppleDomainsPath + "\n" +
		"Restart=on-failure\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateDevices=yes\n" +
		"ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_INET AF_INET6\n" +
		"RestrictNamespaces=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nCapabilityBoundingSet=\nSystemCallArchitectures=native\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
}

// AppleCaddyFile renders the Caddy vhost that proxies the form domain to the local listener.
func AppleCaddyFile(a config.Apple) string {
	return fmt.Sprintf(`# Managed by mailadmin install.
%s {
	header {
		Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "no-referrer"
		X-Frame-Options "DENY"
		-Server
	}
	request_body {
		max_size 4KB
	}
	log {
		output stdout
		format json
	}
	reverse_proxy %s
}
`, a.Domain, a.Listen)
}

// ApplyApple installs the profile form when apple.enabled is set: service user,
// allow-list, unit and Caddy vhost. The allow-list holds the active domains.
func ApplyApple(ctx context.Context, x Exec, a config.Apple, hostname string, domains []string) error {
	if !a.Enabled {
		return nil
	}
	if err := EnsureUser(ctx, x, AppleUser, "/nonexistent", 0); err != nil {
		return err
	}
	if err := RecordUsers(AppleUser); err != nil {
		return err
	}
	if err := applemobile.WriteDomainList(AppleDomainsPath, domains); err != nil {
		return fmt.Errorf("apple allow-list: %w", err)
	}
	if err := writeAtomic(AppleUnitPath, []byte(AppleUnitFile(a, hostname)), 0o644); err != nil {
		return err
	}
	if err := writeAtomic(AppleCaddy, []byte(AppleCaddyFile(a)), 0o644); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := x.Run(ctx, nil, "caddy", "validate", "--config", CaddyfilePath, "--adapter", "caddyfile"); err != nil {
		return fmt.Errorf("caddy validate with apple route: %w", err)
	}
	if err := EnableUnit(ctx, x, AppleUnit); err != nil {
		return err
	}
	if _, err := x.Run(ctx, nil, "systemctl", "restart", "caddy"); err != nil {
		return fmt.Errorf("reload caddy: %w", err)
	}
	return nil
}

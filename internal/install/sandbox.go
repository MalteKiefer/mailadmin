package install

import "fmt"

// sandboxSettings confine the mail services. NoNewPrivileges stays on for all
// of them: none needs setuid. The Dovecot password path does not run here, the
// webmail helper is the only sudo user and it has its own unit.
const sandboxSettings = `PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
NoNewPrivileges=yes`

// SandboxedUnits are the services that get the drop-in.
var SandboxedUnits = []string{"dovecot", "rspamd", "crowdsec", "postgresql"}

// SandboxDropIn returns the systemd drop-in path and content for a unit.
func SandboxDropIn(unit string) (string, string) {
	path := fmt.Sprintf("/etc/systemd/system/%s.service.d/mailadmin-sandbox.conf", unit)
	return path, "# Managed by mailadmin install. Sandbox, tested per service.\n[Service]\n" + sandboxSettings + "\n"
}

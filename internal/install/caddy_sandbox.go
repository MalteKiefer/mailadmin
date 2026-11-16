package install

// CaddySandboxPath is the systemd drop-in that confines the caddy unit.
const CaddySandboxPath = "/etc/systemd/system/caddy.service.d/mailadmin-hardening.conf"

// CaddySandboxConf confines Caddy: it reads its config, writes its certificate
// store under /var/lib/caddy and binds 80 and 443 through one capability. The
// admin API is off in the Caddyfile, so no admin socket or port is needed.
func CaddySandboxConf() string {
	return `# Managed by mailadmin install.
[Service]
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/caddy
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
`
}

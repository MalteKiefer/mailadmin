// Package defaults embeds the default configuration file, so that
// `mailadmin config init` works without network access. The same file is the
// config.default.toml release asset, which `config init` prefers.
package defaults

import _ "embed"

// ConfigTOML is the default configuration, documented key by key.
//
//go:embed config.default.toml
var ConfigTOML []byte

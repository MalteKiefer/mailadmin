// Package migrations embeds the schema migrations that `mailadmin install`
// applies to the mail database, in the order their NNN_ prefixes give.
package migrations

import (
	"embed"
	"fmt"
)

//go:embed *.sql
var files embed.FS

// File is one embedded migration.
type File struct {
	Name string // e.g. 001_baseline.sql
	SQL  string
}

// All returns every migration in apply order.
func All() ([]File, error) {
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	out := make([]File, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, err := files.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		out = append(out, File{Name: e.Name(), SQL: string(body)})
	}
	return out, nil
}

package main

import (
	_ "embed"
	"strings"
)

// scopesYAML is embedded from scopes.yaml at compile time.
//
// server/src/scopes.yaml is a test stub with clearly fake scopes. At Docker
// build time the Dockerfile overwrites it with the real vocabulary from
// lucas42/lucos_auth_scopes before `go build` runs, so the deployed binary
// always embeds the real vocabulary — never this stub.
//
//go:embed scopes.yaml
var scopesYAML []byte

// loadKnownScopes parses the embedded scopes.yaml into a set of valid scope strings.
// It scans for "  - <scope>" lines and strips inline comments.
// No YAML library is used: the format is simple and a parsing dependency on the
// credential store's validation path adds unnecessary complexity.
func loadKnownScopes() map[string]bool {
	scopes := make(map[string]bool)
	for _, line := range strings.Split(string(scopesYAML), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- ") {
			continue
		}
		scope := strings.TrimPrefix(trimmed, "- ")
		// Strip inline comments (e.g. "render-ui    # dev-only: ...").
		if idx := strings.Index(scope, " #"); idx >= 0 {
			scope = scope[:idx]
		}
		scope = strings.TrimSpace(scope)
		if scope != "" {
			scopes[scope] = true
		}
	}
	return scopes
}

// allScopesReadOnly returns true iff every scope in the comma-separated list
// ends with ":read". An empty scopeList is treated as NOT read-only — the
// dev→prod guard uses this to reject scopeless links to production, which
// would otherwise grant unrestricted access.
func allScopesReadOnly(scopeList string) bool {
	if scopeList == "" {
		return false
	}
	for _, s := range strings.Split(scopeList, ",") {
		s = strings.TrimSpace(s)
		if !strings.HasSuffix(s, ":read") {
			return false
		}
	}
	return true
}

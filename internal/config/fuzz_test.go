package config

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{"allowlist":["192.0.2.0/24","::ffff:198.51.100.0/120"],"enforcer_clients":{"watch_uids":[1],"mcp_uids":[1]}}`))
	f.Add([]byte(`{"policy":{"default_ttl":"-1h"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "c.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(p)
		if err != nil {
			return
		}
		// A config that validates keeps the invariants the rest relies on.
		if c.Policy.DefaultTTL <= 0 || c.Policy.DefaultTTL > c.Policy.MaxTTL || c.Policy.AIMinScore < 1 {
			t.Fatalf("invalid policy accepted: %+v", c.Policy)
		}
		seen := map[int]bool{}
		for _, list := range [][]int{c.EnforcerClients.WatchUIDs, c.EnforcerClients.MCPUIDs} {
			for _, u := range list {
				if u == 0 || seen[u] {
					t.Fatalf("uid %d accepted in two roles / as non-admin root", u)
				}
				seen[u] = true
			}
		}
	})
}

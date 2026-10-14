package playbook

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kuramichi2010/nethergate/internal/event"
)

func FuzzLoad(f *testing.F) {
	f.Add([]byte(`[{"id":"a","name":"n","match":{"path_regex":"x"}}]`))
	f.Add([]byte(`[{"id":"a","name":"n","verdict":"allow","match":{"ip_prefixes":["192.0.2.0/24"]}}]`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "pb.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		rules, _ := Load(p)
		for _, r := range rules {
			// Every loaded rule is compiled and must be safe to match.
			r.Matches(event.Event{Kind: event.HTTP, Path: "/x", UA: "y"}, "/x")
			r.Matches(event.Event{Kind: event.SSHFail, User: "root"}, "")
			if r.IsAllow() {
				for _, p := range r.Prefixes() {
					if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
						t.Fatalf("too-wide allow prefix %s loaded", p)
					}
				}
			} else if r.Match.PathRegex == "" && r.Match.UARegex == "" && r.Match.SSHUserRegex == "" {
				t.Fatal("malicious rule without a matcher loaded")
			}
		}
		_, _ = LoadList[Lesson](p)
		_, _ = LoadList[Review](p)
	})
}

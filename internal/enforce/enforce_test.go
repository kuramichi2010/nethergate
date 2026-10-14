package enforce

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michitaka/nethergate/internal/audit"
	"github.com/michitaka/nethergate/internal/config"
	"github.com/michitaka/nethergate/internal/policy"
)

func TestDoBuildsSafeNftArgs(t *testing.T) {
	a, _ := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	s := NewServer(policy.New(config.Default().Policy, nil), a, nil, false)
	var calls [][]string
	s.runNft = func(args ...string) error { calls = append(calls, args); return nil }

	if r := s.Do(Request{Op: "block", IP: "198.51.100.4", Reason: "test", Actor: "ai"}); !r.OK {
		t.Fatal(r.Error)
	}
	if r := s.Do(Request{Op: "block", IP: "198.51.100.4 } ; flush ruleset ; {", Reason: "x"}); r.OK {
		t.Fatal("injection accepted")
	}
	if r := s.Do(Request{Op: "list"}); len(r.Blocks) != 1 {
		t.Fatalf("list: %+v", r)
	}
	if r := s.Do(Request{Op: "unblock", IP: "198.51.100.4", Reason: "fp", Actor: "human"}); !r.OK {
		t.Fatal(r.Error)
	}
	if len(calls) != 2 || !strings.Contains(calls[0][5], "198.51.100.4 timeout 3600s") || calls[1][0] != "delete" {
		t.Fatalf("nft calls: %q", calls)
	}
}

func newTestServer(t *testing.T, state string) (*Server, *[][]string) {
	a, _ := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	s := NewServer(policy.New(config.Default().Policy, nil), a, nil, false)
	s.StatePath = state
	calls := &[][]string{}
	s.runNft = func(args ...string) error { *calls = append(*calls, args); return nil }
	return s, calls
}

func TestRejectsUnknownActorAndZone(t *testing.T) {
	s, calls := newTestServer(t, "")
	if r := s.Do(Request{Op: "block", IP: "198.51.100.4", Reason: "x", Actor: "root"}); r.OK {
		t.Fatal("unknown actor accepted")
	}
	if r := s.Do(Request{Op: "block", IP: "2001:4860::1%x } ; flush ruleset ; {", Reason: "x", Actor: "ai"}); r.OK {
		t.Fatal("zone injection accepted")
	}
	if len(*calls) != 0 {
		t.Fatalf("nft called: %q", *calls)
	}
}

func TestReblockExtendsAndStatePersists(t *testing.T) {
	state := filepath.Join(t.TempDir(), "blocks.json")
	s, calls := newTestServer(t, state)
	s.Do(Request{Op: "block", IP: "198.51.100.4", Reason: "x", Actor: "rules", TTL: 2 * time.Hour})
	s.Do(Request{Op: "block", IP: "198.51.100.4", Reason: "y", Actor: "ai", TTL: time.Hour}) // shorter: no-op
	if len(*calls) != 1 {
		t.Fatalf("shorter re-block touched nft: %q", *calls)
	}
	s.Do(Request{Op: "block", IP: "198.51.100.4", Reason: "z", Actor: "ai", TTL: 3 * time.Hour})
	if len(*calls) != 3 || (*calls)[1][0] != "delete" || !strings.Contains((*calls)[2][5], "timeout 10800s") {
		t.Fatalf("extend: %q", *calls)
	}

	// a restarted enforcer still knows the block and can lift it
	s2, calls2 := newTestServer(t, state)
	if err := s2.LoadState(); err != nil {
		t.Fatal(err)
	}
	if len(*calls2) != 1 || (*calls2)[0][0] != "add" {
		t.Fatalf("restore: %q", *calls2)
	}
	if r := s2.Do(Request{Op: "unblock", IP: "198.51.100.4", Reason: "fp", Actor: "human"}); !r.OK {
		t.Fatal(r.Error)
	}
}

func TestAllowRuleLiftsBlockAndPreventsNew(t *testing.T) {
	dir := t.TempDir()
	a, _ := audit.Open(filepath.Join(dir, "a.jsonl"))
	s := NewServer(policy.New(config.Default().Policy, nil), a, nil, false)
	s.PlaybookPath = filepath.Join(dir, "playbook.json")
	var calls []string
	s.runNft = func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil }

	if r := s.Do(Request{Op: "block", IP: "198.51.100.4", Reason: "looked bad", Actor: "ai"}); !r.OK {
		t.Fatal(r.Error)
	}
	// A human marks the source as fine.
	os.WriteFile(s.PlaybookPath, []byte(`[{"id":"x","name":"partner scanner","verdict":"allow","match":{"ip_prefixes":["198.51.100.0/29"]}}]`), 0o644)
	if r := s.Do(Request{Op: "list"}); len(r.Blocks) != 0 {
		t.Fatalf("block not lifted: %+v", r.Blocks)
	}
	if !strings.HasPrefix(calls[len(calls)-1], "delete element") {
		t.Fatalf("nft not updated: %q", calls)
	}
	if r := s.Do(Request{Op: "block", IP: "198.51.100.5", Reason: "x", Actor: "ai"}); r.OK {
		t.Fatal("blocked an allowlisted address")
	}
}

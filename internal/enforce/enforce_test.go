package enforce

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuramichi2010/nethergate/internal/audit"
	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/detect"
	"github.com/kuramichi2010/nethergate/internal/event"
	"github.com/kuramichi2010/nethergate/internal/playbook"
	"github.com/kuramichi2010/nethergate/internal/policy"
)

// scanner-like activity from ip, so every automated actor is authorised.
func attackIncident(ip netip.Addr, rules []*playbook.Rule) *detect.Incident {
	a := detect.NewAnalyzer(time.Hour)
	a.Rules = rules
	for _, p := range []string{"/.env", "/.git/config", "/?id=1%27%20UNION%20SELECT%201", "/../../etc/passwd"} {
		a.Add(event.Event{Time: time.Now(), Kind: event.HTTP, IP: ip, Path: p, Status: 404, UA: "sqlmap"})
	}
	return a.Get(ip)
}

func newTestServer(t *testing.T, state string) (*Server, *[][]string) {
	a, _ := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	cfg := config.Default().Policy
	s := NewServer(policy.New(cfg, nil), a, config.EnforcerClients{}, cfg, false)
	s.StatePath = state
	s.Verify = func(ip netip.Addr) (*detect.Incident, []*playbook.Rule, error) {
		return attackIncident(ip, nil), nil, nil
	}
	calls := &[][]string{}
	s.runNft = func(args ...string) error { *calls = append(*calls, args); return nil }
	return s, calls
}

func TestDoBuildsSafeNftArgs(t *testing.T) {
	s, calls := newTestServer(t, "")
	if r := s.Do(RoleMCP, Request{Op: "block", IP: "198.51.100.4", Reason: "test"}); !r.OK {
		t.Fatal(r.Error)
	}
	if r := s.Do(RoleAdmin, Request{Op: "block", IP: "198.51.100.4 } ; flush ruleset ; {", Reason: "x"}); r.OK {
		t.Fatal("injection accepted")
	}
	if r := s.Do(RoleMCP, Request{Op: "list"}); len(r.Blocks) != 1 || r.Blocks[0].Actor != "ai" {
		t.Fatalf("list: %+v", r)
	}
	if r := s.Do(RoleAdmin, Request{Op: "unblock", IP: "198.51.100.4", Reason: "fp"}); !r.OK {
		t.Fatal(r.Error)
	}
	if len(*calls) != 2 || !strings.Contains((*calls)[0][5], "198.51.100.4 timeout 3600s") || (*calls)[1][0] != "delete" {
		t.Fatalf("nft calls: %q", *calls)
	}
}

func TestActorComesFromUIDNotRequest(t *testing.T) {
	s, calls := newTestServer(t, "")
	s.Clients = config.EnforcerClients{WatchUIDs: []int{1001}, MCPUIDs: []int{1002}, AdminUIDs: []int{1003}}
	for uid, want := range map[int]Role{0: RoleAdmin, 1001: RoleWatch, 1002: RoleMCP, 1003: RoleAdmin, 4242: RoleNone} {
		if got := s.RoleOf(uid); got != want {
			t.Errorf("uid %d: role %v, want %v", uid, got, want)
		}
	}
	if r := s.Do(RoleNone, Request{Op: "block", IP: "198.51.100.4", Reason: "x"}); r.OK {
		t.Fatal("unknown uid accepted")
	}
	// The AI cannot pass itself off as the playbook to borrow its authority.
	if r := s.Do(RoleMCP, Request{Op: "block", IP: "198.51.100.4", Reason: "x", RuleID: "r1"}); r.OK {
		t.Fatal("mcp accepted with rule_id")
	}
	if r := s.Do(RoleAdmin, Request{Op: "block", IP: "2001:4860::1%x } ; flush ruleset ; {", Reason: "x"}); r.OK {
		t.Fatal("zone injection accepted")
	}
	if len(*calls) != 0 {
		t.Fatalf("nft called: %q", *calls)
	}
}

func TestEnforcerReverifiesIncidents(t *testing.T) {
	s, calls := newTestServer(t, "")
	clean := netip.MustParseAddr("198.51.100.9")
	s.Verify = func(ip netip.Addr) (*detect.Incident, []*playbook.Rule, error) {
		if ip == clean {
			return nil, nil, nil // never touched us
		}
		return attackIncident(ip, nil), nil, nil
	}
	// A compromised MCP process skipping its own checks still cannot block a bystander.
	if r := s.Do(RoleMCP, Request{Op: "block", IP: clean.String(), Reason: "trust me"}); r.OK {
		t.Fatal("ai blocked an IP with no incident")
	}
	if r := s.Do(RoleWatch, Request{Op: "block", IP: clean.String(), Reason: "trust me"}); r.OK {
		t.Fatal("rules blocked an IP with no incident")
	}
	// Humans are not second-guessed.
	if r := s.Do(RoleAdmin, Request{Op: "block", IP: clean.String(), Reason: "known bad"}); !r.OK {
		t.Fatal(r.Error)
	}
	// Logs unreadable: fail closed for automated actors.
	s.Verify = func(netip.Addr) (*detect.Incident, []*playbook.Rule, error) {
		return nil, nil, errors.New("permission denied")
	}
	if r := s.Do(RoleMCP, Request{Op: "block", IP: "198.51.100.10", Reason: "x"}); r.OK {
		t.Fatal("blocked without being able to verify")
	}
	if len(*calls) != 1 {
		t.Fatalf("nft calls: %q", *calls)
	}
}

func TestPlaybookBlockNeedsTriggeredApprovedRule(t *testing.T) {
	s, _ := newTestServer(t, "")
	r := &playbook.Rule{ID: "r1", Name: "env probe", Score: 10, AutoBlock: true, TTL: config.Duration(6 * time.Hour),
		Match: playbook.Match{PathRegex: `^/\.env`}}
	quiet := &playbook.Rule{ID: "r2", Name: "never seen", AutoBlock: true, Match: playbook.Match{PathRegex: `^/nothing-here`}}
	for _, x := range []*playbook.Rule{r, quiet} {
		if err := x.Compile(); err != nil {
			t.Fatal(err)
		}
	}
	rules := []*playbook.Rule{r, quiet}
	s.Verify = func(ip netip.Addr) (*detect.Incident, []*playbook.Rule, error) {
		return attackIncident(ip, rules), rules, nil
	}
	for _, id := range []string{"r2", "nope"} {
		if resp := s.Do(RoleWatch, Request{Op: "block", IP: "198.51.100.4", Reason: "x", RuleID: id}); resp.OK {
			t.Fatalf("rule %s accepted", id)
		}
	}
	if resp := s.Do(RoleWatch, Request{Op: "block", IP: "198.51.100.4", Reason: "x", RuleID: "r1", TTL: 24 * time.Hour}); !resp.OK {
		t.Fatal(resp.Error)
	}
	b := s.Do(RoleAdmin, Request{Op: "list"}).Blocks[0]
	if b.Actor != "playbook" || time.Until(b.Expires) > 6*time.Hour+time.Minute {
		t.Fatalf("%+v", b)
	}
}

func TestAICannotLiftOthersBlocks(t *testing.T) {
	s, _ := newTestServer(t, "")
	s.Do(RoleWatch, Request{Op: "block", IP: "198.51.100.4", Reason: "rules"})
	s.Do(RoleAdmin, Request{Op: "block", IP: "198.51.100.5", Reason: "human"})
	s.Do(RoleMCP, Request{Op: "block", IP: "198.51.100.6", Reason: "ai"})
	for _, ip := range []string{"198.51.100.4", "198.51.100.5"} {
		if r := s.Do(RoleMCP, Request{Op: "unblock", IP: ip, Reason: "false positive"}); r.OK {
			t.Errorf("ai lifted %s", ip)
		}
	}
	if r := s.Do(RoleMCP, Request{Op: "unblock", IP: "198.51.100.6", Reason: "mine"}); !r.OK {
		t.Fatal(r.Error)
	}
	if r := s.Do(RoleWatch, Request{Op: "unblock", IP: "198.51.100.4", Reason: "x"}); r.OK {
		t.Fatal("watch unblocked")
	}
	// Extending a rules block does not hand it to the AI.
	s.Do(RoleMCP, Request{Op: "block", IP: "198.51.100.4", Reason: "longer", TTL: 5 * time.Hour})
	if r := s.Do(RoleMCP, Request{Op: "unblock", IP: "198.51.100.4", Reason: "now mine?"}); r.OK {
		t.Fatal("ai took over a rules block by extending it")
	}
	if r := s.Do(RoleAdmin, Request{Op: "unblock", IP: "198.51.100.4", Reason: "fp"}); !r.OK {
		t.Fatal(r.Error)
	}
}

func TestAuditFailureRefusesFirewallChange(t *testing.T) {
	s, calls := newTestServer(t, "")
	dir := t.TempDir()
	s.Audit, _ = audit.Open(filepath.Join(dir, "gone", "a.jsonl")) // parent missing: every write fails
	if r := s.Do(RoleAdmin, Request{Op: "block", IP: "198.51.100.4", Reason: "x"}); r.OK {
		t.Fatal("blocked without an audit record")
	}
	if len(*calls) != 0 {
		t.Fatalf("nft touched without audit: %q", *calls)
	}
}

func TestReblockExtendsAndStatePersists(t *testing.T) {
	state := filepath.Join(t.TempDir(), "blocks.json")
	s, calls := newTestServer(t, state)
	s.Do(RoleWatch, Request{Op: "block", IP: "198.51.100.4", Reason: "x", TTL: 2 * time.Hour})
	s.Do(RoleMCP, Request{Op: "block", IP: "198.51.100.4", Reason: "y", TTL: time.Hour}) // shorter: no-op
	if len(*calls) != 1 {
		t.Fatalf("shorter re-block touched nft: %q", *calls)
	}
	s.Do(RoleMCP, Request{Op: "block", IP: "198.51.100.4", Reason: "z", TTL: 3 * time.Hour})
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
	if r := s2.Do(RoleAdmin, Request{Op: "unblock", IP: "198.51.100.4", Reason: "fp"}); !r.OK {
		t.Fatal(r.Error)
	}
}

func TestAllowRuleLiftsBlockAndPreventsNew(t *testing.T) {
	s, calls := newTestServer(t, "")
	s.PlaybookPath = filepath.Join(t.TempDir(), "playbook.json")
	if r := s.Do(RoleMCP, Request{Op: "block", IP: "198.51.100.4", Reason: "looked bad"}); !r.OK {
		t.Fatal(r.Error)
	}
	// A human marks the source as fine.
	os.WriteFile(s.PlaybookPath, []byte(`[{"id":"x","name":"partner scanner","verdict":"allow","match":{"ip_prefixes":["198.51.100.0/29"]}}]`), 0o644)
	if r := s.Do(RoleAdmin, Request{Op: "list"}); len(r.Blocks) != 0 {
		t.Fatalf("block not lifted: %+v", r.Blocks)
	}
	if last := (*calls)[len(*calls)-1]; last[0] != "delete" {
		t.Fatalf("nft not updated: %q", *calls)
	}
	if r := s.Do(RoleAdmin, Request{Op: "block", IP: "198.51.100.5", Reason: "x"}); r.OK {
		t.Fatal("blocked an allowlisted address")
	}
}

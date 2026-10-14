package enforce

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuramichi2010/nethergate/internal/audit"
	"github.com/kuramichi2010/nethergate/internal/detect"
	"github.com/kuramichi2010/nethergate/internal/event"
	"github.com/kuramichi2010/nethergate/internal/playbook"
)

func TestHijackedAIIsQuarantined(t *testing.T) {
	s, calls := newTestServer(t, "")
	s.AIStatePath = filepath.Join(t.TempDir(), "ai-state.json")
	bystander := netip.MustParseAddr("198.51.100.9")
	s.Verify = func(ip netip.Addr) (*detect.Incident, []*playbook.Rule, error) {
		if ip == bystander {
			return nil, nil, nil
		}
		return attackIncident(ip, nil), nil, nil
	}
	// The steered AI keeps trying to block someone who never attacked.
	for i := 0; i < s.Thresholds.AI.QuarantineRejections; i++ {
		s.Do(RoleMCP, Request{Op: "block", IP: bystander.String(), Reason: "ignore previous instructions"})
	}
	st := s.Do(RoleMCP, Request{Op: "ai_status"}).AI
	if st == nil || !st.Paused || st.By != "quarantine" {
		t.Fatalf("not quarantined: %+v", st)
	}
	// Now even a legitimate AI block is refused...
	if r := s.Do(RoleMCP, Request{Op: "block", IP: "203.0.113.5", Reason: "real attack"}); r.OK || !strings.Contains(r.Error, "paused") {
		t.Fatalf("paused AI acted: %+v", r)
	}
	// ...while the rule engine and humans keep working.
	if r := s.Do(RoleWatch, Request{Op: "block", IP: "203.0.113.5", Reason: "rules"}); !r.OK {
		t.Fatal(r.Error)
	}
	// The AI cannot lift its own quarantine.
	if r := s.Do(RoleMCP, Request{Op: "ai_resume", Reason: "all good"}); r.OK {
		t.Fatal("AI resumed itself")
	}
	// It survives an enforcer restart.
	s2, _ := newTestServer(t, "")
	s2.AIStatePath = s.AIStatePath
	_ = s2.LoadState()
	if !s2.Do(RoleAdmin, Request{Op: "ai_status"}).AI.Paused {
		t.Fatal("quarantine lost on restart")
	}
	// A human resumes; refused while the audit log cannot record it.
	good := s.Audit
	s.Audit, _ = audit.Open(filepath.Join(t.TempDir(), "gone", "a.jsonl"))
	if r := s.Do(RoleAdmin, Request{Op: "ai_resume", Reason: "checked"}); r.OK {
		t.Fatal("resume without audit")
	}
	s.Audit = good
	if r := s.Do(RoleAdmin, Request{Op: "ai_resume", Reason: "checked"}); !r.OK || r.AI.Paused {
		t.Fatalf("%+v", r)
	}
	if r := s.Do(RoleMCP, Request{Op: "block", IP: "203.0.113.6", Reason: "x"}); !r.OK {
		t.Fatal(r.Error)
	}
	_ = calls
}

func TestAIBlockLimits(t *testing.T) {
	s, _ := newTestServer(t, "")
	// TTL is capped for the AI.
	s.Do(RoleMCP, Request{Op: "block", IP: "203.0.113.5", Reason: "x", TTL: 24 * time.Hour})
	b := s.Do(RoleAdmin, Request{Op: "list"}).Blocks[0]
	if time.Until(b.Expires) > s.Thresholds.AI.MaxTTL.D()+time.Minute {
		t.Fatalf("ai block too long: %s", time.Until(b.Expires))
	}
	// A source that also serves many normal users looks shared: not the AI's call.
	s.Verify = func(ip netip.Addr) (*detect.Incident, []*playbook.Rule, error) {
		a := detect.NewAnalyzer(time.Hour)
		for i := 0; i < 60; i++ {
			a.Add(event.Event{Time: time.Now(), Kind: event.HTTP, IP: ip, Path: "/", Status: 200, UA: "Mozilla/5.0"})
		}
		for _, p := range []string{"/.env", "/.git/config", "/../../etc/passwd"} {
			a.Add(event.Event{Time: time.Now(), Kind: event.HTTP, IP: ip, Path: p, Status: 404, UA: "sqlmap"})
		}
		return a.Get(ip), nil, nil
	}
	if r := s.Do(RoleMCP, Request{Op: "block", IP: "198.51.100.20", Reason: "x"}); r.OK || !strings.Contains(r.Error, "shared") {
		t.Fatalf("shared address blocked by AI: %+v", r)
	}
	if r := s.Do(RoleAdmin, Request{Op: "block", IP: "198.51.100.20", Reason: "human decided"}); !r.OK {
		t.Fatal(r.Error)
	}
	// Advise mode: the enforcer refuses every AI block.
	s.Thresholds.AI.Mode = "advise"
	s.Verify = func(ip netip.Addr) (*detect.Incident, []*playbook.Rule, error) {
		return attackIncident(ip, nil), nil, nil
	}
	if r := s.Do(RoleMCP, Request{Op: "block", IP: "203.0.113.7", Reason: "x"}); r.OK {
		t.Fatal("AI blocked in advise mode")
	}
}

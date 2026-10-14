package enforce

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kuramichi2010/nethergate/internal/detect"
	"github.com/kuramichi2010/nethergate/internal/playbook"
)

func FuzzDo(f *testing.F) {
	f.Add(`{"op":"block","ip":"203.0.113.5","reason":"x"}`, 2)
	f.Add(`{"op":"unblock","ip":"203.0.113.5","reason":"x"}`, 2)
	f.Add(`{"op":"block","ip":"198.51.100.4 } ; flush ruleset ; {","reason":"x","rule_id":"r1"}`, 1)
	f.Add(`{"op":"block","ip":"2001:db8::1%eth0","ttl":-5}`, 3)
	attacker := netip.MustParseAddr("203.0.113.5")
	f.Fuzz(func(t *testing.T, raw string, roleN int) {
		var req Request
		if json.Unmarshal([]byte(raw), &req) != nil {
			return
		}
		s, calls := newTestServer(t, "")
		s.Verify = func(ip netip.Addr) (*detect.Incident, []*playbook.Rule, error) {
			if ip != attacker {
				return nil, nil, nil
			}
			return attackIncident(ip, nil), nil, nil
		}
		// Something placed by the rule engine that the AI must not lift.
		s.Do(RoleWatch, Request{Op: "block", IP: attacker.String(), Reason: "rules", TTL: time.Hour})
		before := len(*calls)
		role := Role(((roleN % 4) + 4) % 4)
		s.Do(role, req)
		for _, c := range (*calls)[before:] {
			if len(c) != 6 || c[1] != "element" || c[2] != "inet" || c[3] != Table {
				t.Fatalf("unexpected nft argv %q", c)
			}
			if role != RoleAdmin && c[0] == "add" && !strings.HasPrefix(c[5], "{ 203.0.113.5 timeout ") {
				t.Fatalf("automated block of a non-attacker: %q", c)
			}
		}
		if role != RoleAdmin {
			// The rules block survives (possibly extended) and keeps its owner.
			b, ok := s.blocks[attacker.String()]
			if !ok {
				t.Fatalf("role %v lifted a rules block with %q", role, raw)
			}
			if rank[b.Actor] < rank["rules"] {
				t.Fatalf("role %v took over a rules block (owner now %q)", role, b.Actor)
			}
		}
	})
}

// Package policy is the hard guardrail between "the AI wants to do X" and
// "X happens". It is enforced inside the privileged enforcer, so a confused
// or prompt-injected model cannot exceed it no matter what it asks for.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/kuramichi2010/nethergate/internal/config"
)

type Action struct {
	Kind   string        `json:"kind"` // "block" | "unblock"
	IP     string        `json:"ip"`
	TTL    time.Duration `json:"ttl"`
	Reason string        `json:"reason"`
	Actor  string        `json:"actor"` // "rules" | "ai" | "human"
}

type Engine struct {
	cfg    config.Policy
	allow  []netip.Prefix
	now    func() time.Time
	mu     sync.Mutex
	recent []time.Time            // all automated blocks (global cap)
	byActr map[string][]time.Time // per-actor quota
	// Allow-rule prefixes approved by humans in the playbook (reloadable).
	extra []netip.Prefix
}

// SetExtraAllow replaces the human-approved allow prefixes from the playbook.
func (e *Engine) SetExtraAllow(p []netip.Prefix) {
	e.mu.Lock()
	e.extra = p
	e.mu.Unlock()
}

// Allowed reports whether ip is covered by the config or playbook allowlist.
func (e *Engine) Allowed(ip netip.Addr) (netip.Prefix, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.allowedLocked(ip)
}

func (e *Engine) allowedLocked(ip netip.Addr) (netip.Prefix, bool) {
	for _, list := range [][]netip.Prefix{e.allow, e.extra} {
		for _, p := range list {
			if p.Contains(ip) {
				return p, true
			}
		}
	}
	return netip.Prefix{}, false
}

func New(cfg config.Policy, allow []netip.Prefix) *Engine {
	return &Engine{cfg: cfg, allow: allow, now: time.Now}
}

var ErrRateLimited = errors.New("block rate limit reached; escalate to a human")

func prune(ts []time.Time, cut time.Time) []time.Time {
	kept := ts[:0]
	for _, t := range ts {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	return kept
}

// MinTTL keeps nft from receiving "timeout 0s" for sub-second TTLs.
const MinTTL = time.Minute

// Ranges that pass IsGlobalUnicast but never belong to a remote attacker.
// 100.64.0.0/10 is carrier-grade NAT and Tailscale: blocking it can lock
// the administrators out of their own VPN.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

// ParseAddr parses a single address and rejects IPv6 zones ("fe80::1%eth0").
// netip accepts arbitrary zone text, which would otherwise reach nft's
// command parser verbatim (e.g. "2001:db8::1%x } ; flush ruleset ; ...").
func ParseAddr(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("not a single IP address: %q", s)
	}
	return ip.Unmap(), nil
}

// Check validates a and, for blocks, consumes rate budget. It returns the
// normalised address and TTL to apply.
func (e *Engine) Check(a *Action) (netip.Addr, time.Duration, error) {
	ip, err := ParseAddr(a.IP)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	switch a.Kind {
	case "unblock":
		return ip, 0, nil
	case "block":
	default:
		return netip.Addr{}, 0, fmt.Errorf("unknown action %q", a.Kind)
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return netip.Addr{}, 0, fmt.Errorf("refusing to block non-public address %s", ip)
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return netip.Addr{}, 0, fmt.Errorf("refusing to block non-public address %s (%s)", ip, p)
		}
	}
	ttl := a.TTL
	if ttl <= 0 {
		ttl = e.cfg.DefaultTTL.D()
	}
	ttl = min(max(ttl, MinTTL), e.cfg.MaxTTL.D())
	if len(a.Reason) == 0 {
		return netip.Addr{}, 0, errors.New("a reason is required for the audit log")
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if p, ok := e.allowedLocked(ip); ok {
		return netip.Addr{}, 0, fmt.Errorf("%s is allowlisted (%s)", ip, p)
	}
	// Humans are accountable and must be able to act during an incident.
	if a.Actor == "human" {
		return ip, ttl, nil
	}
	now := e.now()
	cut := now.Add(-time.Hour)
	if e.byActr == nil {
		e.byActr = map[string][]time.Time{}
	}
	e.recent = prune(e.recent, cut)
	mine := prune(e.byActr[a.Actor], cut)
	e.byActr[a.Actor] = mine
	if q := e.cfg.QuotaPerHour[a.Actor]; q <= 0 || len(mine) >= q {
		return netip.Addr{}, 0, fmt.Errorf("%w (%s quota %d/h)", ErrRateLimited, a.Actor, q)
	}
	if len(e.recent) >= e.cfg.MaxBlocksPerHour {
		return netip.Addr{}, 0, ErrRateLimited
	}
	e.recent = append(e.recent, now)
	e.byActr[a.Actor] = append(mine, now)
	return ip, ttl, nil
}

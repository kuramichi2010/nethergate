package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/michitaka/nethergate/internal/config"
)

func engine() *Engine {
	c := config.Default().Policy
	c.MaxBlocksPerHour = 2
	return New(c, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
}

func TestPolicy(t *testing.T) {
	e := engine()
	refuse := []Action{
		{Kind: "block", IP: "10.0.0.1", Reason: "x"},     // private
		{Kind: "block", IP: "127.0.0.1", Reason: "x"},    // loopback
		{Kind: "block", IP: "203.0.113.9", Reason: "x"},  // allowlisted
		{Kind: "block", IP: "0.0.0.0/0", Reason: "x"},    // range
		{Kind: "block", IP: "198.51.100.1"},              // no reason
		{Kind: "flush", IP: "198.51.100.1", Reason: "x"}, // unknown op
	}
	for _, a := range refuse {
		if _, _, err := e.Check(&a); err == nil {
			t.Errorf("accepted %+v", a)
		}
	}
	_, ttl, err := e.Check(&Action{Kind: "block", IP: "198.51.100.1", Reason: "x", TTL: 999 * time.Hour})
	if err != nil || ttl != 24*time.Hour {
		t.Fatalf("ttl cap: %v %v", ttl, err)
	}
	if _, _, err := e.Check(&Action{Kind: "block", IP: "198.51.100.2", Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.Check(&Action{Kind: "block", IP: "198.51.100.3", Reason: "x"}); err != ErrRateLimited {
		t.Fatalf("rate limit not enforced: %v", err)
	}
}

func TestPolicyRejectsZonesAndSpecialRanges(t *testing.T) {
	e := engine()
	for _, ip := range []string{
		"2001:4860::1%x } ; flush ruleset ; add element inet nethergate block6 { 2001:4860::2", // nft injection via zone
		"2001:4860::1%eth0",
		"100.100.1.1", // CGNAT / Tailscale
	} {
		if _, _, err := e.Check(&Action{Kind: "block", IP: ip, Reason: "x"}); err == nil {
			t.Errorf("accepted %q", ip)
		}
	}
	if _, _, err := e.Check(&Action{Kind: "unblock", IP: "2001:4860::1%x } ; flush ruleset ; {"}); err == nil {
		t.Error("zoned unblock accepted")
	}
}

func TestPolicyMinTTL(t *testing.T) {
	_, ttl, err := engine().Check(&Action{Kind: "block", IP: "198.51.100.1", Reason: "x", TTL: time.Millisecond})
	if err != nil || ttl != MinTTL {
		t.Fatalf("ttl %v %v", ttl, err)
	}
}

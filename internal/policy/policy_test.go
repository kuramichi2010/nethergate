package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/kuramichi2010/nethergate/internal/config"
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
	_, ttl, err := e.Check(&Action{Kind: "block", IP: "198.51.100.1", Reason: "x", Actor: "rules", TTL: 999 * time.Hour})
	if err != nil || ttl != 24*time.Hour {
		t.Fatalf("ttl cap: %v %v", ttl, err)
	}
	if _, _, err := e.Check(&Action{Kind: "block", IP: "198.51.100.2", Reason: "x", Actor: "rules"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.Check(&Action{Kind: "block", IP: "198.51.100.3", Reason: "x", Actor: "rules"}); err != ErrRateLimited {
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
		if _, _, err := e.Check(&Action{Kind: "block", IP: ip, Reason: "x", Actor: "rules"}); err == nil {
			t.Errorf("accepted %q", ip)
		}
	}
	if _, _, err := e.Check(&Action{Kind: "unblock", IP: "2001:4860::1%x } ; flush ruleset ; {"}); err == nil {
		t.Error("zoned unblock accepted")
	}
}

func TestPolicyMinTTL(t *testing.T) {
	_, ttl, err := engine().Check(&Action{Kind: "block", IP: "198.51.100.1", Reason: "x", Actor: "rules", TTL: time.Millisecond})
	if err != nil || ttl != MinTTL {
		t.Fatalf("ttl %v %v", ttl, err)
	}
}

func TestPerActorQuota(t *testing.T) {
	c := config.Default().Policy
	c.MaxBlocksPerHour = 100
	c.QuotaPerHour = map[string]int{"ai": 2, "rules": 3, "playbook": 3}
	e := New(c, nil)
	block := func(actor string, n int) error {
		_, _, err := e.Check(&Action{Kind: "block", IP: fmt.Sprintf("198.51.100.%d", n), Reason: "x", Actor: actor})
		return err
	}
	for i := 1; i <= 2; i++ {
		if err := block("ai", i); err != nil {
			t.Fatal(err)
		}
	}
	if err := block("ai", 3); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("ai quota not enforced: %v", err)
	}
	// The AI exhausting its quota does not stop the rule engine or people.
	if err := block("rules", 4); err != nil {
		t.Fatal(err)
	}
	for i := 10; i < 20; i++ {
		if err := block("human", i); err != nil {
			t.Fatal(err)
		}
	}
	if err := block("intruder", 30); err == nil {
		t.Fatal("actor without a quota accepted")
	}
}

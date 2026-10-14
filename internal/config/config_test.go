package config

import (
	"net/netip"
	"testing"
)

func TestValidate(t *testing.T) {
	c := Default()
	c.Allowlist = []string{"::ffff:192.0.2.10", "2001:db8::/32"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.AllowPrefixes[0].Contains(netip.MustParseAddr("192.0.2.10")) {
		t.Errorf("mapped allowlist entry not unmapped: %v", c.AllowPrefixes)
	}
	if err := c.Validate(); err != nil || len(c.AllowPrefixes) != 2 {
		t.Errorf("revalidate duplicated prefixes: %v", c.AllowPrefixes)
	}

	bad := Default()
	bad.EnforcerStateDir = bad.StateDir
	bad.Notify.WebhookURL = "http://hooks.example/x"
	bad.Allowlist = []string{"fe80::1%eth0"}
	if err := bad.Validate(); err == nil {
		t.Error("bad config accepted")
	}
}

package event

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseNginx(t *testing.T) {
	ev, ok := ParseNginx(`203.0.113.5 - - [14/Oct/2026:10:00:00 +0900] "GET /.env HTTP/1.1" 404 153 "-" "sqlmap/1.8"`)
	if !ok || ev.IP.String() != "203.0.113.5" || ev.Path != "/.env" || ev.Status != 404 || ev.UA != "sqlmap/1.8" {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
	if _, ok := ParseNginx("garbage"); ok {
		t.Fatal("garbage parsed")
	}
	// malformed request line from a scanner is still recorded
	ev, ok = ParseNginx(`198.51.100.1 - - [14/Oct/2026:10:00:00 +0000] "\x16\x03\x01" 400 0 "-" "-"`)
	if !ok || ev.Status != 400 {
		t.Fatalf("malformed request: %+v %v", ev, ok)
	}
}

func TestParseSSHD(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		line string
		kind Kind
		user string
	}{
		{"Oct 14 11:59:00 host sshd[12]: Failed password for root from 203.0.113.9 port 4242 ssh2", SSHFail, "root"},
		{"Oct 14 11:59:00 host sshd[12]: Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2", SSHInvalidUser, "admin"},
		{"2026-10-14T11:59:00+0000 host sshd[12]: Invalid user oracle from 203.0.113.9 port 4242", SSHInvalidUser, "oracle"},
		{"Oct 14 11:59:00 host sshd[12]: Accepted publickey for deploy from 203.0.113.9 port 4242 ssh2", SSHAccepted, "deploy"},
	}
	for _, c := range cases {
		ev, ok := ParseSSHD(c.line, now)
		if !ok || ev.Kind != c.kind || ev.User != c.user || ev.IP.String() != "203.0.113.9" {
			t.Errorf("%q: got %+v ok=%v", c.line, ev, ok)
		}
		if ev.Time.Hour() != 11 {
			t.Errorf("%q: time %v", c.line, ev.Time)
		}
	}
}

func TestParseSSHDSpoofAndSession(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct{ line, ip, user string }{
		// attacker-chosen user names that embed a fake source address
		{"Oct 14 11:59:00 host sshd[12]: Failed password for invalid user x from 8.8.8.8 port 1 from 203.0.113.9 port 4242 ssh2", "203.0.113.9", "x from 8.8.8.8 port 1"},
		{"Oct 14 11:59:00 host sshd[12]: Invalid user y from 8.8.8.8 port 1 from 203.0.113.9 port 4242", "203.0.113.9", "y from 8.8.8.8 port 1"},
		{"Oct 14 11:59:00 host sshd[12]: Invalid user sshd[1]: Failed password for root from 8.8.8.8 port 1 ssh2 from 203.0.113.9 port 4242", "203.0.113.9", "sshd[1]: Failed password for root from 8.8.8.8 port 1 ssh2"},
		// OpenSSH >= 9.8
		{"Oct 14 11:59:00 host sshd-session[77]: Failed password for root from 203.0.113.9 port 4242 ssh2", "203.0.113.9", "root"},
		{"Oct 14 11:59:00 host sshd-session[77]: Accepted publickey for deploy from 203.0.113.9 port 4242 ssh2: ED25519 SHA256:abc", "203.0.113.9", "deploy"},
	}
	for _, c := range cases {
		ev, ok := ParseSSHD(c.line, now)
		if !ok || ev.IP.String() != c.ip || ev.User != c.user {
			t.Errorf("%q: got %+v ok=%v", c.line, ev, ok)
		}
	}
	if _, ok := ParseNginx(`fe80::1%eth0 - - [14/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`); ok {
		t.Error("zoned address accepted")
	}
}

func TestResolveClientBehindProxy(t *testing.T) {
	cdn := []netip.Prefix{netip.MustParsePrefix("173.245.48.0/20"), netip.MustParsePrefix("2400:cb00::/32")}
	line := func(peer, xff string) string {
		return peer + ` - - [14/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 1 "-" "sqlmap" "` + xff + `"`
	}
	cases := []struct {
		peer, xff, want string
		ok              bool
	}{
		{"173.245.48.10", "203.0.113.5", "203.0.113.5", true},                // via CDN
		{"173.245.48.10", "1.1.1.1, 203.0.113.5", "203.0.113.5", true},       // client-forged left part ignored
		{"173.245.48.10", "203.0.113.5, 173.245.48.99", "203.0.113.5", true}, // CDN hop skipped
		{"198.51.100.7", "1.1.1.1", "198.51.100.7", true},                    // direct: header is forged, ignored
		{"173.245.48.10", "", "", false},                                     // CDN without a client: never score the CDN
		{"173.245.48.10", "173.245.48.11", "", false},                        // only proxies
		{"173.245.48.10", "not-an-ip", "", false},                            // garbage
		{"2400:cb00::1", "[2001:db8::7]:4431", "2001:db8::7", true},          // IPv6 with port
		{"173.245.48.10", "::ffff:203.0.113.9", "203.0.113.9", true},         // mapped
	}
	for _, c := range cases {
		ev, ok := ParseNginxProxy(line(c.peer, c.xff))
		if !ok {
			t.Fatalf("parse %q", c.peer)
		}
		got := ev.ResolveClient(cdn)
		if got != c.ok || (got && ev.IP.String() != c.want) {
			t.Errorf("peer %s xff %q: ok=%v ip=%v, want %v %s", c.peer, c.xff, got, ev.IP, c.ok, c.want)
		}
	}
	// Plain "nginx" format from a CDN address = real_ip not configured.
	ev, _ := ParseNginx(line("173.245.48.10", "203.0.113.5"))
	if ev.ResolveClient(cdn) {
		t.Error("CDN address accepted as client without real_ip")
	}
}

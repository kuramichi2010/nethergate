package event

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func FuzzParseNginx(f *testing.F) {
	f.Add(`203.0.113.5 - - [14/Oct/2026:10:00:00 +0900] "GET /.env HTTP/1.1" 404 153 "-" "sqlmap/1.8"`)
	f.Add(`198.51.100.1 - - [14/Oct/2026:10:00:00 +0000] "\x16\x03\x01" 400 0 "-" "-"`)
	f.Add(`::ffff:192.0.2.1 - - [14/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "a"`)
	f.Fuzz(func(t *testing.T, line string) {
		ev, ok := ParseNginx(line)
		if !ok {
			return
		}
		if !ev.IP.IsValid() || ev.IP.Zone() != "" || ev.IP.Is4In6() {
			t.Fatalf("bad source address %v from %q", ev.IP, line)
		}
		// The source is the first field, which the attacker cannot choose.
		if first := strings.SplitN(line, " ", 2)[0]; netip.MustParseAddr(first).Unmap() != ev.IP {
			t.Fatalf("source %v is not the first field of %q", ev.IP, line)
		}
	})
}

func FuzzParseSSHD(f *testing.F) {
	f.Add("root", "Failed password for")
	f.Add("x from 1.2.3.4 port 1", "Failed password for invalid user")
	f.Add("admin from 10.0.0.1", "Invalid user")
	f.Add("deploy", "Accepted publickey for")
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	real := netip.MustParseAddr("203.0.113.9")
	f.Fuzz(func(t *testing.T, user, verb string) {
		// The attacker controls the user name (and anything else in the
		// message); sshd appends the real address. Whatever the user
		// name contains, a parsed event must carry the real address.
		line := "Oct 14 11:59:00 host sshd[12]: " + verb + " " + user + " from 203.0.113.9 port 4242 ssh2"
		if ev, ok := ParseSSHD(line, now); ok && ev.IP != real {
			t.Fatalf("user %q made the parser report %v instead of %v", user, ev.IP, real)
		}
		// Arbitrary lines must never panic.
		ParseSSHD(user, now)
		ParseSSHD(verb+user, now)
	})
}

func FuzzResolveClient(f *testing.F) {
	f.Add("173.245.48.10", "1.1.1.1, 203.0.113.5")
	f.Add("198.51.100.7", "203.0.113.5")
	f.Add("173.245.48.10", "[2001:db8::1]:80,173.245.48.1")
	cdn := []netip.Prefix{netip.MustParsePrefix("173.245.48.0/20")}
	f.Fuzz(func(t *testing.T, peer, xff string) {
		ev, ok := ParseNginxProxy(peer + ` - - [14/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "a" "` + xff + `"`)
		if !ok {
			return
		}
		if !ev.ResolveClient(cdn) {
			return
		}
		// The result is never a trusted proxy, and a direct (untrusted)
		// peer can never be replaced by what it put in the header.
		if cdn[0].Contains(ev.IP) {
			t.Fatalf("resolved to the CDN itself: %v", ev.IP)
		}
		if !cdn[0].Contains(ev.Peer) && ev.IP != ev.Peer {
			t.Fatalf("untrusted peer %v replaced by forged header -> %v", ev.Peer, ev.IP)
		}
	})
}

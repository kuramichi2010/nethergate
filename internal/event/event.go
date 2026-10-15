// Package event parses log lines into normalised security events.
package event

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Kind string

const (
	HTTP           Kind = "http"
	SSHFail        Kind = "ssh_fail"
	SSHInvalidUser Kind = "ssh_invalid_user"
	SSHAccepted    Kind = "ssh_accepted"
)

type Event struct {
	Time   time.Time
	Kind   Kind
	IP     netip.Addr
	Method string
	Path   string
	Status int
	UA     string
	User   string
	// nginx_proxy only: the TCP peer and the X-Forwarded-For header as
	// logged. IP is the peer until ResolveClient picks the client.
	Peer         netip.Addr
	ForwardedFor string
}

var nginxRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) \S+ "[^"]*" "([^"]*)"`)

var nginxProxyRe = regexp.MustCompile(nginxRe.String() + ` "([^"]*)"`)

// ParseNginxProxy parses combined + a trailing quoted X-Forwarded-For.
func ParseNginxProxy(line string) (Event, bool) {
	f, rest, ok := splitCombined(line)
	if !ok || !strings.HasPrefix(rest, ` "`) {
		return Event{}, false
	}
	end := strings.IndexByte(rest[2:], '"')
	if end < 0 {
		return Event{}, false
	}
	ev, ok := combinedEvent(f)
	if !ok {
		return Event{}, false
	}
	ev.Peer, ev.ForwardedFor = ev.IP, rest[2:2+end]
	return ev, true
}

// isSpace is Go regexp's \s: [\t\n\f\r ].
func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r' }

// token reads \S+ followed by one space (the delimiter).
func token(s string) (tok, rest string, ok bool) {
	i := 0
	for i < len(s) && !isSpace(s[i]) {
		i++
	}
	if i == 0 || i >= len(s) || s[i] != ' ' {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// quoted reads "[^"]*" and returns the inside.
func quoted(s string) (in, rest string, ok bool) {
	if len(s) == 0 || s[0] != '"' {
		return "", "", false
	}
	end := strings.IndexByte(s[1:], '"')
	if end < 0 {
		return "", "", false
	}
	return s[1 : 1+end], s[2+end:], true
}

// splitCombined is a hand-written equivalent of nginxRe (it runs on every
// line; the regexp was half the cost of a scan). FuzzSplitCombinedMatchesRegexp
// checks that both always agree. f = ip, time, request, status, ua.
func splitCombined(line string) (f [5]string, rest string, ok bool) {
	if f[0], rest, ok = token(line); !ok {
		return
	}
	for i := 0; i < 2; i++ {
		if _, rest, ok = token(rest); !ok {
			return
		}
	}
	if len(rest) < 2 || rest[0] != '[' {
		return f, "", false
	}
	end := strings.IndexByte(rest, ']')
	if end < 2 || !strings.HasPrefix(rest[end:], "] ") {
		return f, "", false
	}
	f[1], rest = rest[1:end], rest[end+2:]
	if f[2], rest, ok = quoted(rest); !ok || !strings.HasPrefix(rest, " ") {
		return f, "", false
	}
	rest = rest[1:]
	if len(rest) < 4 || rest[3] != ' ' {
		return f, "", false
	}
	for i := 0; i < 3; i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return f, "", false
		}
	}
	f[3], rest = rest[:3], rest[4:]
	if _, rest, ok = token(rest); !ok {
		return
	}
	if _, rest, ok = quoted(rest); !ok || !strings.HasPrefix(rest, " ") {
		return f, "", false
	}
	if f[4], rest, ok = quoted(rest[1:]); !ok {
		return
	}
	return f, rest, true
}

// ResolveClient decides the client address of an HTTP event given the
// trusted proxies in front of this server:
//   - a peer that is not a trusted proxy is the client; any
//     X-Forwarded-For it sent is ignored (anyone can forge the header);
//   - behind a trusted proxy, the client is the right-most address in
//     X-Forwarded-For that is not itself a trusted proxy (entries further
//     left were written by the client and can be forged).
//
// It returns false when the peer is a trusted proxy but no client can be
// determined (e.g. nginx real_ip not configured): such events must not be
// scored, or the CDN itself would look like the attacker.
func (ev *Event) ResolveClient(proxies []netip.Prefix) bool {
	if ev.Kind != HTTP || len(proxies) == 0 || !inPrefixes(ev.IP, proxies) {
		return true
	}
	parts := strings.Split(ev.ForwardedFor, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, ok := parseHop(strings.TrimSpace(parts[i]))
		if !ok {
			return false // garbage where a proxy should have written an address
		}
		if !inPrefixes(a, proxies) {
			ev.IP = a
			return true
		}
	}
	return false
}

func parseHop(s string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil && ap.Addr().Zone() == "" {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ParseNginx parses the nginx/apache "combined" log format.
func ParseNginx(line string) (Event, bool) {
	f, _, ok := splitCombined(line)
	if !ok {
		return Event{}, false
	}
	return combinedEvent(f)
}

func combinedEvent(f [5]string) (Event, bool) {
	ip, err := parseIP(f[0])
	if err != nil {
		return Event{}, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", f[1])
	if err != nil {
		return Event{}, false
	}
	status, _ := strconv.Atoi(f[3])
	ev := Event{Time: t, Kind: HTTP, IP: ip, Status: status, UA: f[4]}
	// Request line: "METHOD PATH PROTO", but scanners send garbage too.
	if m, after, ok := strings.Cut(f[2], " "); ok {
		ev.Method = m
		ev.Path, _, _ = strings.Cut(after, " ")
	} else {
		ev.Path = f[2]
	}
	return ev, true
}

func parseIP(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err == nil && ip.Zone() != "" {
		err = strconv.ErrSyntax
	}
	return ip.Unmap(), err
}

// The user name is attacker-controlled and sshd logs it verbatim, so a name
// like "x from 192.0.2.1 port 1" must not decide the source address. The
// message regexes are anchored at both ends and the user group is greedy,
// so the address is always taken from the last, sshd-written "from X port N".
var (
	sshPrefixRe   = regexp.MustCompile(`\bsshd(?:-session)?\[\d+\]: `) // OpenSSH >= 9.8 logs as sshd-session
	sshTail       = ` from (\S+) port \d+(?: ssh2)?(?:: .*|\s+\[preauth\])?\s*$`
	sshFailRe     = regexp.MustCompile(`^Failed \S+ for (invalid user )?(.*)` + sshTail)
	sshInvalidRe  = regexp.MustCompile(`^Invalid user (.*) from (\S+)(?: port \d+)?\s*$`)
	sshAcceptedRe = regexp.MustCompile(`^Accepted \S+ for (\S+)` + sshTail)
	isoPrefixRe   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\S+)\s`)
)

// ParseSSHD parses OpenSSH auth log lines (syslog or journalctl -o short-iso).
func ParseSSHD(line string, now time.Time) (Event, bool) {
	var ev Event
	var ipStr string
	// The first sshd prefix is the one syslog wrote; anything later is message text.
	loc := sshPrefixRe.FindStringIndex(line)
	if loc == nil {
		return Event{}, false
	}
	msg := line[loc[1]:]
	if m := sshFailRe.FindStringSubmatch(msg); m != nil {
		ev.Kind, ev.User, ipStr = SSHFail, m[2], m[3]
		if m[1] != "" {
			ev.Kind = SSHInvalidUser
		}
	} else if m := sshInvalidRe.FindStringSubmatch(msg); m != nil {
		ev.Kind, ev.User, ipStr = SSHInvalidUser, m[1], m[2]
	} else if m := sshAcceptedRe.FindStringSubmatch(msg); m != nil {
		ev.Kind, ev.User, ipStr = SSHAccepted, m[1], m[2]
	} else {
		return Event{}, false
	}
	ip, err := parseIP(ipStr)
	if err != nil {
		return Event{}, false
	}
	ev.IP = ip
	ev.Time = parseSyslogTime(line, now)
	return ev, true
}

func parseSyslogTime(line string, now time.Time) time.Time {
	if m := isoPrefixRe.FindStringSubmatch(line); m != nil {
		for _, f := range []string{time.RFC3339Nano, "2006-01-02T15:04:05-0700"} {
			if t, err := time.Parse(f, m[1]); err == nil {
				return t
			}
		}
	}
	if len(line) >= 15 {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], now.Location()); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) { // log from last year
				t = t.AddDate(-1, 0, 0)
			}
			return t
		}
	}
	return now
}

// Parse dispatches by format name.
func Parse(format, line string, now time.Time) (Event, bool) {
	switch format {
	case "nginx":
		return ParseNginx(line)
	case "nginx_proxy":
		return ParseNginxProxy(line)
	case "sshd":
		return ParseSSHD(line, now)
	}
	return Event{}, false
}

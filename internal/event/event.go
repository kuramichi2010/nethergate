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
}

var nginxRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) \S+ "[^"]*" "([^"]*)"`)

// ParseNginx parses the nginx/apache "combined" log format.
func ParseNginx(line string) (Event, bool) {
	m := nginxRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	ip, err := parseIP(m[1])
	if err != nil {
		return Event{}, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		return Event{}, false
	}
	status, _ := strconv.Atoi(m[4])
	ev := Event{Time: t, Kind: HTTP, IP: ip, Status: status, UA: m[5]}
	// Request line: "METHOD PATH PROTO", but scanners send garbage too.
	parts := strings.SplitN(m[3], " ", 3)
	if len(parts) >= 2 {
		ev.Method, ev.Path = parts[0], parts[1]
	} else {
		ev.Path = m[3]
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
	case "sshd":
		return ParseSSHD(line, now)
	}
	return Event{}, false
}

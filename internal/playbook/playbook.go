// Package playbook is nethergate's memory of special attack patterns.
//
// When the AI (or a person) handles an unusual attack, it records the
// pattern and how it was handled as a rule. Approved rules are loaded at
// startup and matched by the rule engine on every event, so the next
// occurrence is recognised and, if the rule says so, blocked immediately,
// without waiting for AI triage.
//
// Rules written by the AI are only *proposals*: they live in a file the
// agent can write, and do nothing until a human approves them into the
// approved file, which the agent can read but not modify. A prompt-injected
// model therefore cannot plant a rule that blocks legitimate users.
//
// Rules have a verdict. "malicious" rules (the default) raise the score
// and may auto-block. "allow" rules are exceptions written down by people:
// matching traffic is not counted as an attack, and an allow rule with
// ip_prefixes is also enforced by the enforcer, which refuses to block (and
// lifts existing blocks on) those addresses.
package playbook

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"syscall"
	"time"

	"github.com/michitaka/nethergate/internal/config"
	"github.com/michitaka/nethergate/internal/event"
)

const (
	MaxRegexLen = 300
	MaxScore    = 60
	MaxRules    = 500
	MaxText     = 2000
)

type Match struct {
	PathRegex    string `json:"path_regex,omitempty"`     // URL-decoded request path
	UARegex      string `json:"ua_regex,omitempty"`       // User-Agent
	SSHUserRegex string `json:"ssh_user_regex,omitempty"` // username in failed SSH logins
	// Source ranges (allow rules only), e.g. a partner's scanner or our monitoring.
	IPPrefixes []string `json:"ip_prefixes,omitempty"`
	// Events from one source needed before the rule counts (default 1).
	MinHits int `json:"min_hits,omitempty"`
}

// Key identifies what a rule matches, to detect duplicates.
func (m Match) Key() string {
	b, _ := json.Marshal(m)
	return string(b)
}

const (
	Malicious = "malicious"
	Allow     = "allow"
)

type Rule struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`       // what the pattern is
	Handling    string          `json:"handling"`          // what was done / what to do next time
	Verdict     string          `json:"verdict,omitempty"` // "malicious" (default) | "allow"
	Match       Match           `json:"match"`
	Score       int             `json:"score"`      // added to the incident score
	AutoBlock   bool            `json:"auto_block"` // block on match without waiting for AI
	TTL         config.Duration `json:"ttl,omitempty"`
	ExampleIP   string          `json:"example_ip,omitempty"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	ApprovedAt  *time.Time      `json:"approved_at,omitempty"`

	path, ua, sshUser *regexp.Regexp
	prefixes          []netip.Prefix
}

func (r *Rule) IsAllow() bool { return r.Verdict == Allow }

// Prefixes returns the parsed ip_prefixes of a compiled rule.
func (r *Rule) Prefixes() []netip.Prefix { return r.prefixes }

// Compile validates r and prepares its regexes. Go's regexp is RE2, so a
// rule cannot cause catastrophic backtracking (ReDoS) on attacker input.
func (r *Rule) Compile() error {
	m := &r.Match
	switch r.Verdict {
	case "":
		r.Verdict = Malicious
	case Malicious, Allow:
	default:
		return fmt.Errorf("verdict must be %q or %q", Malicious, Allow)
	}
	if r.IsAllow() {
		if r.Score != 0 || r.AutoBlock || r.TTL != 0 {
			return errors.New("allow rules cannot have score, auto_block or ttl")
		}
		if m.PathRegex == "" && m.UARegex == "" && m.SSHUserRegex == "" && len(m.IPPrefixes) == 0 {
			return errors.New("allow rule needs ip_prefixes and/or a regex")
		}
	} else {
		if len(m.IPPrefixes) > 0 {
			return errors.New("ip_prefixes are only for allow rules (blocking is always per single IP)")
		}
		if m.PathRegex == "" && m.UARegex == "" && m.SSHUserRegex == "" {
			return errors.New("at least one of path_regex, ua_regex, ssh_user_regex is required")
		}
	}
	if len(m.IPPrefixes) > 64 {
		return errors.New("at most 64 ip_prefixes per rule")
	}
	r.prefixes = nil
	for _, s := range m.IPPrefixes {
		p, err := ParsePrefix(s)
		if err != nil {
			return err
		}
		r.prefixes = append(r.prefixes, p)
	}
	if m.SSHUserRegex != "" && (m.PathRegex != "" || m.UARegex != "") {
		return errors.New("ssh_user_regex cannot be combined with HTTP fields")
	}
	if r.Name == "" || len(r.Name) > 100 || len(r.Description) > MaxText || len(r.Handling) > MaxText {
		return fmt.Errorf("name is required (<=100 bytes); description/handling <= %d bytes", MaxText)
	}
	if r.Score < 0 || r.Score > MaxScore {
		return fmt.Errorf("score must be 0..%d", MaxScore)
	}
	if m.MinHits < 0 || m.MinHits > 10000 {
		return errors.New("min_hits must be 0..10000")
	}
	if m.MinHits == 0 {
		m.MinHits = 1
	}
	if r.TTL < 0 {
		return errors.New("ttl must be >= 0")
	}
	var err error
	compile := func(name, s string) *regexp.Regexp {
		if s == "" || err != nil {
			return nil
		}
		if len(s) > MaxRegexLen {
			err = fmt.Errorf("%s longer than %d bytes", name, MaxRegexLen)
			return nil
		}
		re, cerr := regexp.Compile(s)
		if cerr != nil {
			err = fmt.Errorf("%s: %w", name, cerr)
			return nil
		}
		if re.MatchString("") {
			err = fmt.Errorf("%s matches the empty string (would match everything)", name)
			return nil
		}
		return re
	}
	r.path = compile("path_regex", m.PathRegex)
	r.ua = compile("ua_regex", m.UARegex)
	r.sshUser = compile("ssh_user_regex", m.SSHUserRegex)
	return err
}

// ParsePrefix accepts "a.b.c.d", "a.b.c.d/n" or IPv6 forms; refuses /0-style
// ranges so one allow rule cannot exempt the whole Internet.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, err2 := netip.ParseAddr(s)
		if err2 != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("invalid ip prefix %q", s)
		}
		p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16) {
		return netip.Prefix{}, fmt.Errorf("ip prefix %s is too wide", s)
	}
	return p.Masked(), nil
}

// Matches reports whether ev matches r. decodedPath is the URL-decoded path.
func (r *Rule) Matches(ev event.Event, decodedPath string) bool {
	if len(r.prefixes) > 0 {
		in := false
		for _, p := range r.prefixes {
			in = in || p.Contains(ev.IP)
		}
		if !in {
			return false
		}
		if r.path == nil && r.ua == nil && r.sshUser == nil {
			return true // IP-only allow rule: everything from these sources
		}
	}
	switch ev.Kind {
	case event.HTTP:
		if r.sshUser != nil || (r.path == nil && r.ua == nil) {
			return false
		}
		return (r.path == nil || r.path.MatchString(decodedPath)) && (r.ua == nil || r.ua.MatchString(ev.UA))
	case event.SSHFail, event.SSHInvalidUser:
		return r.sshUser != nil && r.sshUser.MatchString(ev.User)
	}
	return false
}

// Traffic that a rule must never match: ordinary pages, browsers and the
// crawlers that keep a public site findable.
var benignPaths = []string{"/", "/index.html", "/favicon.ico", "/robots.txt", "/sitemap.xml",
	"/login", "/search?q=hello", "/api/v1/items/42", "/static/app.js", "/images/logo.png", "/about"}
var benignUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
}

// CheckBenign rejects malicious rules that match ordinary traffic.
func (r *Rule) CheckBenign() error {
	if r.IsAllow() {
		return nil
	}
	for _, p := range benignPaths {
		for _, ua := range benignUAs {
			if r.Matches(event.Event{Kind: event.HTTP, Path: p, UA: ua}, p) {
				return fmt.Errorf("rule matches ordinary traffic (path %q, UA %q); make it more specific", p, ua)
			}
		}
	}
	return nil
}

func (r *Rule) EffectiveTTL(def time.Duration) time.Duration {
	if r.TTL > 0 {
		return r.TTL.D()
	}
	return def
}

func NewID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Load reads a rule file. A missing file is an empty playbook. Invalid
// rules are skipped and reported, so one bad entry does not stop defence.
func Load(path string) ([]*Rule, []error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, []error{err}
	}
	var raw []*Rule
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, []error{fmt.Errorf("%s: %w", path, err)}
	}
	var out []*Rule
	var errs []error
	seen := map[string]bool{}
	for i, r := range raw {
		if r == nil || r.ID == "" || seen[r.ID] {
			errs = append(errs, fmt.Errorf("%s: rule #%d: missing or duplicate id", path, i))
			continue
		}
		if err := r.Compile(); err != nil {
			errs = append(errs, fmt.Errorf("%s: rule %s: %w", path, r.ID, err))
			continue
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	if len(out) > MaxRules {
		errs = append(errs, fmt.Errorf("%s: only the first %d rules are used", path, MaxRules))
		out = out[:MaxRules]
	}
	return out, errs
}

// Save writes rules atomically (temp file + rename).
func Save(path string, rules []*Rule, mode os.FileMode) error {
	if rules == nil {
		rules = []*Rule{}
	}
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), mode)
}

// Update runs fn on the rules in path under an exclusive lock, then saves.
func Update(path string, mode os.FileMode, fn func([]*Rule) ([]*Rule, error)) error {
	lf, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o660)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	rules, errs := Load(path)
	if len(errs) > 0 {
		// Saving would silently drop the broken entries: make a person fix them.
		return fmt.Errorf("refusing to modify %s until it loads cleanly: %w", path, errors.Join(errs...))
	}
	rules, err = fn(rules)
	if err != nil {
		return err
	}
	return Save(path, rules, mode)
}

// Package detect turns events into per-source incidents with a risk score
// and a best-effort guess at what kind of actor is behind them.
//
// The rules are deterministic and cheap so they run on every event; the AI
// is only consulted for incidents that the rules already consider risky.
package detect

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kuramichi2010/nethergate/internal/event"
	"github.com/kuramichi2010/nethergate/internal/playbook"
	"github.com/kuramichi2010/nethergate/internal/sanitize"
)

type Signature struct {
	Category string
	Weight   int
	Re       *regexp.Regexp
}

var pathSignatures = []Signature{
	{"sqli", 25, regexp.MustCompile(`(?i)(union(\s|\+|/\*\*/)+select|'\s*or\s*'?\d|\bor\s+1=1|sleep\(\d|benchmark\(|information_schema|extractvalue\(|waitfor\s+delay)`)},
	{"path_traversal", 25, regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self/|win\.ini|boot\.ini)`)},
	{"rce", 35, regexp.MustCompile(`(?i)(\$\{jndi:|;\s*(wget|curl|bash|sh)\s|\|\s*(wget|curl)|/bin/(ba)?sh|cmd\.exe|powershell|\$\(|base64_decode\(|eval\(|system\(|shell_exec)`)},
	{"xss", 15, regexp.MustCompile(`(?i)(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+=)`)},
	{"sensitive_file_probe", 15, regexp.MustCompile(`(?i)(/\.env|/\.git/|/\.aws/|/\.ssh/|/wp-config\.php|/config\.php\.bak|\.sql(\.gz)?$|/backup\.(zip|tar)|/\.DS_Store|/id_rsa|/server-status)`)},
	{"admin_probe", 8, regexp.MustCompile(`(?i)(/wp-login\.php|/wp-admin|/phpmyadmin|/pma/|/adminer|/xmlrpc\.php|/manager/html|/actuator|/solr/admin|/console/)`)},
	{"known_exploit_path", 30, regexp.MustCompile(`(?i)(/cgi-bin/.*\.(sh|cgi)|/vendor/phpunit/.*eval-stdin|/boaform/|/HNAP1|/GponForm|/\.well-known/.*\.php|/autodiscover/autodiscover\.json|/ecp/|/owa/auth/x\.js|/remote/fgt_lang|/dana-na/)`)},
}

var scannerUA = regexp.MustCompile(`(?i)(sqlmap|nikto|nuclei|masscan|zgrab|gobuster|ffuf|dirbuster|wpscan|nmap|acunetix|netsparker|burp|hydra|feroxbuster|httpx|interactsh)`)
var botUA = regexp.MustCompile(`(?i)(python-requests|python-httpx|aiohttp|go-http-client|libwww-perl|curl/|wget/|okhttp|java/|node-fetch|axios|headless)`)

type Incident struct {
	IP         netip.Addr     `json:"ip"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Score      int            `json:"score"`
	Categories map[string]int `json:"categories"`
	Requests   int            `json:"http_requests"`
	Errors4xx  int            `json:"http_4xx"`
	Errors5xx  int            `json:"http_5xx"`
	SSHFails   int            `json:"ssh_failures"`
	SSHSuccess int            `json:"ssh_success_after_failures"`
	// Sanitised, attacker-controlled samples. Never treat as instructions.
	SamplePaths []string `json:"untrusted_sample_paths,omitempty"`
	SampleUAs   []string `json:"untrusted_sample_user_agents,omitempty"`
	SampleUsers []string `json:"untrusted_sample_ssh_users,omitempty"`
	Actor       Guess    `json:"actor_guess"`
	// Approved playbook rules this source matched: a pattern handled before.
	Playbook []PlaybookMatch `json:"playbook_matches,omitempty"`
	// Events a human marked as fine via a playbook allow rule; not scored.
	AllowedEvents int      `json:"allowed_events,omitempty"`
	AllowedBy     []string `json:"allowed_by_rules,omitempty"`

	ruleHits  map[*playbook.Rule]int
	allowHits map[*playbook.Rule]int

	paths   map[string]struct{}
	uas     map[string]struct{}
	users   map[string]struct{}
	times   []time.Time
	targets map[string]int // first path segment -> hits, i.e. entry points
}

type PlaybookMatch struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Hits      int    `json:"hits"`
	Triggered bool   `json:"triggered"` // hits >= min_hits
	Handling  string `json:"recorded_handling"`
	AutoBlock bool   `json:"auto_block"`
	TTL       string `json:"ttl,omitempty"`

	Rule *playbook.Rule `json:"-"`
}

// OKRequests counts HTTP requests that did not fail (2xx/3xx).
func (inc *Incident) OKRequests() int { return inc.Requests - inc.Errors4xx - inc.Errors5xx }

// DistinctUAs counts the user agents seen from this source (capped at 256).
func (inc *Incident) DistinctUAs() int { return len(inc.uas) }

// Hits reports how many events from this source matched r (malicious or
// allow rule) and whether that reached the rule's min_hits.
func (inc *Incident) Hits(r *playbook.Rule) (int, bool) {
	n := inc.ruleHits[r] + inc.allowHits[r]
	return n, n > 0 && n >= r.Match.MinHits
}

// Triggered returns the playbook rules whose min_hits this source reached.
func (inc *Incident) Triggered() []PlaybookMatch {
	var out []PlaybookMatch
	for _, m := range inc.Playbook {
		if m.Triggered {
			out = append(out, m)
		}
	}
	return out
}

type Guess struct {
	Type       string   `json:"type"`
	Confidence string   `json:"confidence"`
	Reasons    []string `json:"reasons"`
	EntryPoint []string `json:"entry_points"`
}

type Analyzer struct {
	Window time.Duration
	// Trusted proxies (CDN) in front of this server, for client resolution.
	Proxies []netip.Prefix
	// HTTP events from a trusted proxy whose client could not be
	// determined; they are dropped (a sign of a proxy misconfiguration).
	ProxyUnresolved int
	// Approved playbook rules, matched on every event.
	Rules     []*playbook.Rule
	incidents map[netip.Addr]*Incident
}

func NewAnalyzer(window time.Duration) *Analyzer {
	return &Analyzer{Window: window, incidents: map[netip.Addr]*Incident{}}
}

const maxSamples = 8

func addSample(set map[string]struct{}, list *[]string, s string) {
	if s == "" || len(set) >= 256 {
		return
	}
	if _, ok := set[s]; ok {
		return
	}
	set[s] = struct{}{}
	if len(*list) < maxSamples {
		*list = append(*list, sanitize.Untrusted(s))
	}
}

func (a *Analyzer) Add(ev event.Event) {
	inc := a.incidents[ev.IP]
	if inc == nil {
		inc = &Incident{IP: ev.IP, FirstSeen: ev.Time, Categories: map[string]int{},
			paths: map[string]struct{}{}, uas: map[string]struct{}{}, users: map[string]struct{}{}, targets: map[string]int{}}
		a.incidents[ev.IP] = inc
	}
	if ev.Time.Before(inc.FirstSeen) {
		inc.FirstSeen = ev.Time
	}
	if ev.Time.After(inc.LastSeen) {
		inc.LastSeen = ev.Time
	}
	decoded := ""
	if ev.Kind == event.HTTP {
		decoded = ev.Path
		for i := 0; i < 2; i++ { // double-encoding is common in evasion
			if d, err := url.QueryUnescape(decoded); err == nil {
				decoded = d
			}
		}
	}
	// A human said this traffic is fine: remember it, but do not score it.
	for _, r := range a.Rules {
		if r.IsAllow() && r.Matches(ev, decoded) {
			if inc.allowHits == nil {
				inc.allowHits = map[*playbook.Rule]int{}
			}
			inc.allowHits[r]++
			inc.AllowedEvents++
			return
		}
	}
	if len(inc.times) < 4096 {
		inc.times = append(inc.times, ev.Time)
	}
	switch ev.Kind {
	case event.HTTP:
		inc.Requests++
		switch {
		case ev.Status >= 500:
			inc.Errors5xx++
		case ev.Status >= 400:
			inc.Errors4xx++
		}
		matched := a.matchRules(inc, ev, decoded)
		for _, s := range pathSignatures {
			if s.Re.MatchString(decoded) {
				inc.Categories[s.Category]++
				matched = true
			}
		}
		if scannerUA.MatchString(ev.UA) {
			inc.Categories["scanner_tool_ua"]++
		} else if botUA.MatchString(ev.UA) {
			inc.Categories["scripted_client_ua"]++
		}
		if ev.UA == "" || ev.UA == "-" {
			inc.Categories["empty_ua"]++
		}
		if matched || ev.Status >= 400 {
			addSample(inc.paths, &inc.SamplePaths, ev.Path)
		}
		addSample(inc.uas, &inc.SampleUAs, ev.UA)
		addTarget(inc, entryPoint(ev.Path))
	case event.SSHFail, event.SSHInvalidUser:
		inc.SSHFails++
		if ev.Kind == event.SSHInvalidUser {
			inc.Categories["ssh_invalid_user"]++
		}
		addSample(inc.users, &inc.SampleUsers, ev.User)
		addTarget(inc, "ssh")
		a.matchRules(inc, ev, "")
	case event.SSHAccepted:
		if inc.SSHFails > 0 {
			inc.SSHSuccess++
		}
		addTarget(inc, "ssh")
	}
}

func (a *Analyzer) matchRules(inc *Incident, ev event.Event, decoded string) bool {
	hit := false
	for _, r := range a.Rules {
		if !r.IsAllow() && r.Matches(ev, decoded) {
			if inc.ruleHits == nil {
				inc.ruleHits = map[*playbook.Rule]int{}
			}
			inc.ruleHits[r]++
			hit = true
		}
	}
	return hit
}

// addTarget counts hits per entry point, keeping at most 256 distinct ones
// so a single source cannot grow memory with endless unique paths.
func addTarget(inc *Incident, ep string) {
	if _, ok := inc.targets[ep]; ok || len(inc.targets) < 256 {
		inc.targets[ep]++
	}
}

func entryPoint(p string) string {
	p = strings.SplitN(p, "?", 2)[0]
	segs := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 3)
	if len(segs) >= 2 && segs[1] != "" {
		return sanitize.Untrusted("/" + segs[0] + "/" + segs[1])
	}
	return sanitize.Untrusted("/" + segs[0])
}

// Incidents scores everything and returns incidents seen after since,
// highest score first.
func (a *Analyzer) Incidents(since time.Time, minScore int) []*Incident {
	var out []*Incident
	for _, inc := range a.incidents {
		if inc.LastSeen.Before(since) {
			continue
		}
		score(inc)
		if inc.Score >= minScore {
			out = append(out, inc)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

func (a *Analyzer) Get(ip netip.Addr) *Incident {
	inc := a.incidents[ip]
	if inc != nil {
		score(inc)
	}
	return inc
}

// Has reports whether ip has an incident, without rescoring it.
func (a *Analyzer) Has(ip netip.Addr) bool {
	_, ok := a.incidents[ip]
	return ok
}

// Prune drops incidents not seen since cutoff (bounded memory in watch mode).
func (a *Analyzer) Prune(cutoff time.Time) {
	for ip, inc := range a.incidents {
		if inc.LastSeen.Before(cutoff) {
			delete(a.incidents, ip)
		}
	}
}

func weightOf(cat string) int {
	for _, s := range pathSignatures {
		if s.Category == cat {
			return s.Weight
		}
	}
	switch cat {
	case "scanner_tool_ua":
		return 30
	case "scripted_client_ua":
		return 3
	case "empty_ua":
		return 3
	case "ssh_invalid_user":
		return 4
	}
	return 0
}

func score(inc *Incident) {
	s := 0
	for cat, n := range inc.Categories {
		w := weightOf(cat)
		// diminishing returns: first hit counts fully, repeats add a little
		s += w + min(n-1, 10)*w/5
	}
	if inc.Requests >= 20 && inc.Errors4xx*100/inc.Requests >= 70 {
		s += 20 // enumeration: mostly misses
	}
	if len(inc.paths) >= 50 {
		s += 15
	}
	if inc.SSHFails >= 5 {
		s += 20 + min(inc.SSHFails/10, 30)
	}
	if inc.SSHSuccess > 0 {
		s += 50 // possible successful brute force: escalate to a human
	}
	if r := peakPerMinute(inc.times); r >= 120 {
		s += 20
	} else if r >= 30 {
		s += 8
	}
	inc.Playbook = inc.Playbook[:0]
	for r, n := range inc.ruleHits {
		m := PlaybookMatch{ID: r.ID, Name: r.Name, Hits: n, Triggered: n >= r.Match.MinHits,
			Handling: r.Handling, AutoBlock: r.AutoBlock, Rule: r}
		if r.TTL > 0 {
			m.TTL = r.TTL.D().String()
		}
		if m.Triggered {
			s += r.Score
		}
		inc.Playbook = append(inc.Playbook, m)
	}
	sort.Slice(inc.Playbook, func(i, j int) bool { return inc.Playbook[i].ID < inc.Playbook[j].ID })
	inc.AllowedBy = inc.AllowedBy[:0]
	for r := range inc.allowHits {
		inc.AllowedBy = append(inc.AllowedBy, r.ID+" ("+r.Name+")")
	}
	sort.Strings(inc.AllowedBy)
	inc.Score = min(s, 100)
	inc.Actor = guess(inc)
}

func peakPerMinute(ts []time.Time) int {
	if len(ts) < 2 {
		return len(ts)
	}
	sorted := append([]time.Time(nil), ts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })
	best, j := 0, 0
	for i := range sorted {
		for sorted[i].Sub(sorted[j]) > time.Minute {
			j++
		}
		best = max(best, i-j+1)
	}
	return best
}

// guess is a heuristic classification. It is an estimate for the report,
// not an attribution: source IPs are routinely proxies, VPNs or victims.
func guess(inc *Incident) Guess {
	g := Guess{Type: "unknown", Confidence: "low"}
	cats := len(inc.Categories)
	exploitCats := 0
	for _, c := range []string{"sqli", "path_traversal", "rce", "xss", "known_exploit_path"} {
		if inc.Categories[c] > 0 {
			exploitCats++
		}
	}
	rate := peakPerMinute(inc.times)
	trig := inc.Triggered()
	switch {
	case inc.SSHSuccess > 0:
		g.Type, g.Confidence = "credential brute force with SUCCESSFUL login (possible compromise)", "high"
		g.Reasons = append(g.Reasons, "ssh login accepted after failures")
	case len(trig) > 0:
		g.Type, g.Confidence = "known pattern from playbook: "+trig[0].Name, "high"
		for _, m := range trig {
			g.Reasons = append(g.Reasons, fmt.Sprintf("matched approved playbook rule %s (%s) %d times", m.ID, m.Name, m.Hits))
		}
	case inc.SSHFails >= 5 && inc.Requests == 0:
		g.Type, g.Confidence = "ssh credential brute force (botnet / opportunistic)", "high"
		g.Reasons = append(g.Reasons, "repeated ssh failures, no web activity")
	case inc.Categories["scanner_tool_ua"] > 0:
		g.Type, g.Confidence = "off-the-shelf vulnerability scanner", "high"
		g.Reasons = append(g.Reasons, "user agent matches a known scanning tool")
	case exploitCats >= 3 && len(inc.paths) >= 20 && rate < 120:
		g.Type, g.Confidence = "adaptive / possibly AI-assisted targeted attack", "medium"
		g.Reasons = append(g.Reasons,
			"many distinct exploit classes against varied paths",
			"request rate is moderate rather than mass-scanner speed")
	case inc.Categories["known_exploit_path"] > 0 && len(inc.paths) < 10:
		g.Type, g.Confidence = "mass exploitation bot (single known CVE spray)", "medium"
		g.Reasons = append(g.Reasons, "probes a few well-known exploit paths only")
	case len(inc.paths) >= 50 && inc.Requests > 0 && inc.Errors4xx*100/inc.Requests >= 70:
		g.Type, g.Confidence = "content discovery / directory brute force", "medium"
		g.Reasons = append(g.Reasons, "many distinct paths, mostly 4xx")
	case cats > 0:
		g.Type = "opportunistic probing"
		g.Reasons = append(g.Reasons, "matched generic attack signatures")
	}
	type kv struct {
		k string
		v int
	}
	var eps []kv
	for k, v := range inc.targets {
		eps = append(eps, kv{k, v})
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].v > eps[j].v })
	for i := 0; i < len(eps) && i < 5; i++ {
		g.EntryPoint = append(g.EntryPoint, eps[i].k)
	}
	return g
}

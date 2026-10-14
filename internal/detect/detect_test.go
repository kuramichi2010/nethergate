package detect

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/michitaka/nethergate/internal/event"
	"github.com/michitaka/nethergate/internal/playbook"
)

var t0 = time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)

func TestScannerScoresHigh(t *testing.T) {
	a := NewAnalyzer(24 * time.Hour)
	ip := netip.MustParseAddr("203.0.113.5")
	for i, p := range []string{"/.env", "/.git/config", "/?id=1%27%20UNION%20SELECT%201", "/../../etc/passwd"} {
		a.Add(event.Event{Time: t0.Add(time.Duration(i) * time.Second), Kind: event.HTTP, IP: ip, Path: p, Status: 404, UA: "sqlmap/1.8"})
	}
	inc := a.Get(ip)
	if inc.Score < 80 {
		t.Fatalf("score %d, cats %v", inc.Score, inc.Categories)
	}
	if inc.Actor.Type != "off-the-shelf vulnerability scanner" {
		t.Errorf("actor %q", inc.Actor.Type)
	}
}

func TestNormalBrowsingScoresLow(t *testing.T) {
	a := NewAnalyzer(24 * time.Hour)
	ip := netip.MustParseAddr("198.51.100.7")
	for i := 0; i < 30; i++ {
		a.Add(event.Event{Time: t0.Add(time.Duration(i) * 10 * time.Second), Kind: event.HTTP, IP: ip,
			Path: fmt.Sprintf("/articles/%d", i), Status: 200, UA: "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"})
	}
	if s := a.Get(ip).Score; s != 0 {
		t.Fatalf("benign traffic scored %d", s)
	}
}

func TestSSHBruteForceThenSuccess(t *testing.T) {
	a := NewAnalyzer(24 * time.Hour)
	ip := netip.MustParseAddr("192.0.2.200")
	for i := 0; i < 20; i++ {
		a.Add(event.Event{Time: t0.Add(time.Duration(i) * time.Second), Kind: event.SSHInvalidUser, IP: ip, User: fmt.Sprint("u", i)})
	}
	a.Add(event.Event{Time: t0.Add(time.Minute), Kind: event.SSHAccepted, IP: ip, User: "root"})
	inc := a.Get(ip)
	// Critical (human escalation) but below default auto_block_score (90):
	// the success may be the admin, so a person decides, not the rules.
	if inc.Score < 80 || inc.Score >= 90 || inc.Actor.Confidence != "high" || inc.SSHSuccess != 1 {
		t.Fatalf("%+v", inc)
	}
}

func TestPlaybookRuleRaisesScoreAndNamesPattern(t *testing.T) {
	r := &playbook.Rule{ID: "r1", Name: "graphql introspection", Handling: "block 6h", Score: 40,
		Match: playbook.Match{PathRegex: `__schema`, MinHits: 2}}
	if err := r.Compile(); err != nil {
		t.Fatal(err)
	}
	a := NewAnalyzer(time.Hour)
	a.Rules = []*playbook.Rule{r}
	ip := netip.MustParseAddr("203.0.113.77")
	ev := event.Event{Time: t0, Kind: event.HTTP, IP: ip, Path: "/graphql?q=%7B__schema%7D", Status: 200, UA: "Mozilla/5.0"}
	a.Add(ev)
	if inc := a.Get(ip); inc.Score != 0 || len(inc.Triggered()) != 0 || len(inc.Playbook) != 1 {
		t.Fatalf("below min_hits: %+v", inc.Playbook)
	}
	a.Add(ev)
	inc := a.Get(ip)
	if inc.Score != 40 || len(inc.Triggered()) != 1 || inc.Actor.Type != "known pattern from playbook: graphql introspection" {
		t.Fatalf("score %d actor %q", inc.Score, inc.Actor.Type)
	}
}

func TestAllowRuleExemptsOnlyItsTraffic(t *testing.T) {
	allow := &playbook.Rule{ID: "a1", Name: "our uptime monitor", Verdict: playbook.Allow,
		Match: playbook.Match{IPPrefixes: []string{"192.0.2.0/28"}}}
	if err := allow.Compile(); err != nil {
		t.Fatal(err)
	}
	a := NewAnalyzer(time.Hour)
	a.Rules = []*playbook.Rule{allow}
	mon, other := netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.200")
	for _, ip := range []netip.Addr{mon, other} {
		a.Add(event.Event{Time: t0, Kind: event.HTTP, IP: ip, Path: "/.env", Status: 404, UA: "nuclei"})
	}
	if inc := a.Get(mon); inc.Score != 0 || inc.AllowedEvents != 1 || len(inc.AllowedBy) != 1 {
		t.Fatalf("allowed source scored: %+v", inc)
	}
	if inc := a.Get(other); inc.Score < 30 {
		t.Fatalf("source outside the allow range exempted: %d", inc.Score)
	}
}

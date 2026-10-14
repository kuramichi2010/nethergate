package watch

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/detect"
	"github.com/kuramichi2010/nethergate/internal/enforce"
	"github.com/kuramichi2010/nethergate/internal/event"
	"github.com/kuramichi2010/nethergate/internal/logscan"
	"github.com/kuramichi2010/nethergate/internal/playbook"
)

// fakeEnforcer records the requests it receives.
func fakeEnforcer(t *testing.T) (string, chan enforce.Request) {
	sock := filepath.Join(t.TempDir(), "e.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan enforce.Request, 10)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var r enforce.Request
			_ = json.NewDecoder(c).Decode(&r)
			got <- r
			_ = json.NewEncoder(c).Encode(enforce.Response{OK: true})
			c.Close()
		}
	}()
	return sock, got
}

func TestNoAutoBlockAfterSuccessfulLogin(t *testing.T) {
	sock, got := fakeEnforcer(t)
	cfg := config.Default()
	cfg.EnforcerSocket = sock
	cfg.Policy.AutoBlockScore = 50
	d := &Daemon{Cfg: cfg, blocked: map[netip.Addr]time.Time{}, triaged: map[netip.Addr]time.Time{}, notified: map[netip.Addr]int{}}

	a := detect.NewAnalyzer(time.Hour)
	now := time.Now()
	admin, scanner := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")
	for i := 0; i < 10; i++ {
		a.Add(event.Event{Time: now, Kind: event.SSHFail, IP: admin, User: "me"})
		a.Add(event.Event{Time: now, Kind: event.SSHFail, IP: scanner, User: "root"})
	}
	a.Add(event.Event{Time: now, Kind: event.SSHAccepted, IP: admin, User: "me"})
	a.Add(event.Event{Time: now, Kind: event.HTTP, IP: scanner, Path: "/.env", UA: "sqlmap"})
	for _, inc := range a.Incidents(now.Add(-time.Minute), 0) {
		d.handle(context.Background(), inc, now)
	}
	select {
	case r := <-got:
		if r.IP != scanner.String() {
			t.Fatalf("blocked %s", r.IP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scanner not blocked")
	}
	select {
	case r := <-got:
		t.Fatalf("unexpected block of %s", r.IP)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestScanSkipsMissingLogAndPartialLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "access.log")
	now := time.Now().UTC()
	ts := now.Format("02/Jan/2006:15:04:05 -0700")
	line := `203.0.113.5 - - [` + ts + `] "GET /.env HTTP/1.1" 404 1 "-" "x"` + "\n"
	if err := os.WriteFile(p, []byte(strings.Repeat(line, 3)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Logs = []config.LogSource{{Path: filepath.Join(dir, "missing.log"), Format: "sshd"}, {Path: p, Format: "nginx"}}
	cfg.MaxScanBytes = int64(len(line)*2 + 5) // lands mid-line
	a, err := logscan.Scan(cfg, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if inc := a.Get(netip.MustParseAddr("203.0.113.5")); inc == nil || inc.Requests != 2 {
		t.Fatalf("%+v", inc)
	}
}

func TestPlaybookAutoBlockSkipsAIAndUsesRuleTTL(t *testing.T) {
	sock, got := fakeEnforcer(t)
	cfg := config.Default()
	cfg.EnforcerSocket = sock
	cfg.Policy.AutoBlockScore = 0          // rule engine off: only the playbook acts
	cfg.Triage.Command = []string{"false"} // would run if triage were reached
	cfg.Triage.MinScore = 1
	d := &Daemon{Cfg: cfg, blocked: map[netip.Addr]time.Time{}, triaged: map[netip.Addr]time.Time{},
		notified: map[netip.Addr]int{}, triageBusy: make(chan struct{}, 1), notifyQ: make(chan string, 8)}

	r := &playbook.Rule{ID: "r1", Name: "graphql introspection", Score: 40, AutoBlock: true,
		TTL: config.Duration(6 * time.Hour), Match: playbook.Match{PathRegex: `__schema`, MinHits: 2}}
	if err := r.Compile(); err != nil {
		t.Fatal(err)
	}
	a := detect.NewAnalyzer(time.Hour)
	a.Rules = []*playbook.Rule{r}
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.77")
	add := func() {
		a.Add(event.Event{Time: now, Kind: event.HTTP, IP: ip, Path: "/graphql?q={__schema{types{name}}}", Status: 200, UA: "Mozilla/5.0"})
	}
	add()
	for _, inc := range a.Incidents(now.Add(-time.Minute), 0) {
		d.handle(context.Background(), inc, now)
	}
	select {
	case r := <-got:
		t.Fatalf("blocked before min_hits: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
	add()
	for _, inc := range a.Incidents(now.Add(-time.Minute), 0) {
		d.handle(context.Background(), inc, now)
	}
	select {
	case req := <-got:
		if req.IP != ip.String() || req.TTL != 6*time.Hour || req.RuleID != "r1" {
			t.Fatalf("%+v", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("playbook rule did not block")
	}
	if _, ok := d.triaged[ip]; ok {
		t.Fatal("AI triage ran for a pattern the playbook already handles")
	}
}

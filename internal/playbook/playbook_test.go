package playbook

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/michitaka/nethergate/internal/event"
)

func TestCompileAndMatch(t *testing.T) {
	r := &Rule{ID: "a", Name: "x", Match: Match{PathRegex: `__schema`, UARegex: `(?i)python`}}
	if err := r.Compile(); err != nil || r.Match.MinHits != 1 {
		t.Fatal(err)
	}
	ev := event.Event{Kind: event.HTTP, UA: "python-requests/2.32"}
	if !r.Matches(ev, "/graphql?q=__schema") {
		t.Error("should match")
	}
	ev.UA = "Mozilla/5.0"
	if r.Matches(ev, "/graphql?q=__schema") {
		t.Error("all fields must match")
	}
	if r.Matches(event.Event{Kind: event.SSHFail, User: "__schema"}, "") {
		t.Error("http rule matched ssh event")
	}

	bad := []*Rule{
		{Name: "x"}, // no matcher
		{Name: "x", Match: Match{PathRegex: "a*"}},                            // matches empty
		{Name: "x", Match: Match{PathRegex: "x", SSHUserRegex: "y"}},          // mixed
		{Name: "", Match: Match{PathRegex: "x"}},                              // no name
		{Name: "x", Score: 61, Match: Match{PathRegex: "x"}},                  // score cap
		{Name: "x", Match: Match{PathRegex: string(make([]byte, 400)) + "x"}}, // too long
	}
	for i, r := range bad {
		if err := r.Compile(); err == nil {
			t.Errorf("bad rule %d compiled", i)
		}
	}
}

func TestLoadSkipsInvalidAndUpdateRefusesBrokenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pb.json")
	os.WriteFile(p, []byte(`[{"id":"ok","name":"n","match":{"path_regex":"x"}},{"id":"bad","name":"n","match":{"path_regex":"("}}]`), 0o600)
	rules, errs := Load(p)
	if len(rules) != 1 || len(errs) != 1 {
		t.Fatalf("%d rules, %v", len(rules), errs)
	}
	if err := Update(p, 0o600, func(r []*Rule) ([]*Rule, error) { return r, nil }); err == nil {
		t.Fatal("Update would silently drop the broken rule")
	}
	if rules, errs := Load(filepath.Join(t.TempDir(), "none.json")); rules != nil || errs != nil {
		t.Fatal("missing file should be an empty playbook")
	}
}

func TestAllowRules(t *testing.T) {
	ok := &Rule{ID: "a", Name: "monitoring", Verdict: Allow, Match: Match{IPPrefixes: []string{"192.0.2.0/24"}}}
	if err := ok.Compile(); err != nil {
		t.Fatal(err)
	}
	in := netip.MustParseAddr("192.0.2.7")
	if !ok.Matches(event.Event{Kind: event.HTTP, IP: in, Path: "/.env"}, "/.env") ||
		!ok.Matches(event.Event{Kind: event.SSHFail, IP: in}, "") {
		t.Error("ip-only allow rule should match any event from the range")
	}
	if ok.Matches(event.Event{Kind: event.HTTP, IP: netip.MustParseAddr("198.51.100.1")}, "/") {
		t.Error("matched outside the range")
	}
	narrowed := &Rule{ID: "b", Name: "health", Verdict: Allow, Match: Match{IPPrefixes: []string{"192.0.2.7"}, PathRegex: `^/healthz$`}}
	if err := narrowed.Compile(); err != nil {
		t.Fatal(err)
	}
	if narrowed.Matches(event.Event{Kind: event.HTTP, IP: in}, "/.env") || !narrowed.Matches(event.Event{Kind: event.HTTP, IP: in}, "/healthz") {
		t.Error("ip+path allow rule must require both")
	}
	bad := []*Rule{
		{Name: "x", Verdict: Allow, Match: Match{IPPrefixes: []string{"0.0.0.0/0"}}},            // whole Internet
		{Name: "x", Verdict: Allow, Match: Match{IPPrefixes: []string{"::/8"}}},                 // too wide v6
		{Name: "x", Verdict: Allow, Score: 10, Match: Match{IPPrefixes: []string{"192.0.2.1"}}}, // allow with score
		{Name: "x", Verdict: Allow, AutoBlock: true, Match: Match{IPPrefixes: []string{"192.0.2.1"}}},
		{Name: "x", Match: Match{PathRegex: "x", IPPrefixes: []string{"192.0.2.1"}}}, // malicious range
		{Name: "x", Verdict: "maybe", Match: Match{PathRegex: "x"}},
	}
	for i, r := range bad {
		if err := r.Compile(); err == nil {
			t.Errorf("bad allow rule %d compiled", i)
		}
	}
}

func TestLessonsAndReviewsLists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lessons.json")
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.1"} {
		if err := UpdateList(p, 0o600, func(l []Lesson) ([]Lesson, error) { return append(l, Lesson{IP: ip, Note: ip}), nil }); err != nil {
			t.Fatal(err)
		}
	}
	l, _ := LoadList[Lesson](p)
	if got := LessonsFor(l, "192.0.2.1"); len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	os.WriteFile(p, []byte("{broken"), 0o600)
	if err := UpdateList(p, 0o600, func(l []Lesson) ([]Lesson, error) { return nil, nil }); err == nil {
		t.Fatal("overwrote an unreadable lessons file")
	}
}

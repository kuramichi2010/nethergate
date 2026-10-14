package forward

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kuramichi2010/nethergate/internal/audit"
)

type memSink struct {
	fail   bool
	events []Event
}

func (m *memSink) Name() string { return "mem" }
func (m *memSink) Send(ev []Event) error {
	if m.fail {
		return errors.New("siem down")
	}
	m.events = append(m.events, ev...)
	return nil
}

func (m *memSink) of(typ string) []Event {
	var out []Event
	for _, e := range m.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func setup(t *testing.T) (string, *audit.Log, *memSink, *Forwarder) {
	dir := t.TempDir()
	p := filepath.Join(dir, "enforcer-audit.jsonl")
	l, _ := audit.Open(p)
	sink := &memSink{}
	f := &Forwarder{Files: []string{p}, Sinks: []Sink{sink}, StatePath: filepath.Join(dir, "state.json"), Host: "h1"}
	return p, l, sink, f
}

func TestOutageLosesNothingAndAnchorsMatch(t *testing.T) {
	p, l, sink, f := setup(t)
	for i := 0; i < 3; i++ {
		_ = l.Write("ai", "block", map[string]any{"i": i}, "ok")
	}
	sink.fail = true
	now := time.Now()
	f.Step(now)
	if len(sink.events) != 0 || f.Stats().Errors != 1 {
		t.Fatalf("sent during outage: %d", len(sink.events))
	}
	_ = l.Write("ai", "block", map[string]any{"i": 3}, "ok")
	sink.fail = false
	f.Step(now.Add(time.Second)) // still backing off
	if len(sink.events) != 0 {
		t.Fatal("ignored backoff")
	}
	f.Step(now.Add(time.Minute))
	recs := sink.of("audit")
	if len(recs) != 4 || recs[0].N != 1 || recs[3].N != 4 {
		t.Fatalf("got %d records", len(recs))
	}
	n, h, _ := audit.HeadOf(p)
	anchors := sink.of("anchor")
	if last := anchors[len(anchors)-1]; last.N != n || last.Hash != h {
		t.Fatalf("anchor %+v, head %d %s", last, n, h)
	}
	// A restarted forwarder resumes from the saved offset: nothing resent.
	f2 := &Forwarder{Files: f.Files, Sinks: []Sink{sink}, StatePath: f.StatePath, Host: "h1"}
	f2.Step(now.Add(2 * time.Minute))
	if len(sink.of("audit")) != 4 {
		t.Fatal("records re-sent after restart")
	}
}

func TestPartialLineWaits(t *testing.T) {
	p, _, sink, f := setup(t)
	os.WriteFile(p, []byte(`{"hash":"a"}`+"\n"+`{"hash":"b"`), 0o600)
	f.Step(time.Now())
	if len(sink.of("audit")) != 1 {
		t.Fatalf("%+v", sink.events)
	}
}

func TestTruncationAndDeletionAreReported(t *testing.T) {
	p, l, sink, f := setup(t)
	for i := 0; i < 5; i++ {
		_ = l.Write("ai", "block", nil, "ok")
	}
	now := time.Now()
	f.Step(now)
	b, _ := os.ReadFile(p)
	lines := strings.SplitAfter(string(b), "\n")
	os.WriteFile(p, []byte(strings.Join(lines[:2], "")), 0o600) // attacker truncates
	f.Step(now.Add(time.Second))
	tam := sink.of("tamper")
	if len(tam) != 1 || tam[0].N != 5 || !strings.Contains(tam[0].Detail, "shrank") {
		t.Fatalf("%+v", tam)
	}
	os.Remove(p)
	f.Step(now.Add(2 * time.Second))
	if tam := sink.of("tamper"); len(tam) != 2 || !strings.Contains(tam[1].Detail, "disappeared") {
		t.Fatalf("%+v", tam)
	}
}

func TestSyslogFraming(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		lenStr, _ := r.ReadString(' ')
		n, _ := strconv.Atoi(strings.TrimSpace(lenStr))
		buf := make([]byte, n)
		_, _ = io.ReadFull(r, buf)
		got <- string(buf)
	}()
	s, _ := NewSyslogSink(ln.Addr().String(), "", "", true)
	ev := Event{Type: "tamper", Time: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), Host: "web1", File: "a.jsonl", Detail: "x"}
	if err := s.Send([]Event{ev}); err != nil {
		t.Fatal(err)
	}
	msg := <-got
	if !strings.HasPrefix(msg, "<81>1 2026-10-14T00:00:00Z web1 nethergate - tamper - {") {
		t.Fatalf("%q", msg)
	}
}

func TestHTTPSplunk(t *testing.T) {
	var auth, body string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}))
	defer srv.Close()
	t.Setenv("HEC_TOKEN", "s3cret")
	s, err := NewHTTPSink(srv.URL+"/services/collector", "splunk_hec", "HEC_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	s.Client = srv.Client()
	if err := s.Send([]Event{{Type: "audit", File: "a.jsonl", N: 1, Record: json.RawMessage(`{"hash":"x"}`)}}); err != nil {
		t.Fatal(err)
	}
	if auth != "Splunk s3cret" || !strings.Contains(body, `"sourcetype":"nethergate:audit"`) {
		t.Fatalf("auth %q body %s", auth, body)
	}
	if _, err := NewHTTPSink("http://plain.example/x", "", ""); err == nil {
		t.Fatal("plaintext http accepted")
	}
	if strings.Contains(s.Name(), "collector") {
		t.Fatal("sink name leaks the URL path")
	}
}

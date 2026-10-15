package enforce

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCF is a minimal Cloudflare IP Access Rules API.
type fakeCF struct {
	mu      sync.Mutex
	rules   map[string]map[string]string // id -> {value, notes}
	next    int
	calls   []string
	failAll bool
}

func (f *fakeCF) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(403)
			return
		}
		if f.failAll {
			w.WriteHeader(500)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"down"}]}`)
			return
		}
		base := "/zones/z1/firewall/access_rules/rules"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == base:
			var body struct {
				Mode          string
				Configuration struct{ Target, Value string }
				Notes         string
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, rule := range f.rules {
				if rule["value"] == body.Configuration.Value {
					w.WriteHeader(400)
					fmt.Fprint(w, `{"success":false,"errors":[{"code":10009,"message":"duplicate"}]}`)
					return
				}
			}
			f.next++
			id := fmt.Sprintf("r%d", f.next)
			f.rules[id] = map[string]string{"value": body.Configuration.Value, "notes": body.Notes, "target": body.Configuration.Target}
			fmt.Fprintf(w, `{"success":true,"result":{"id":%q}}`, id)
		case r.Method == http.MethodGet && r.URL.Path == base:
			v := r.URL.Query().Get("configuration.value")
			var out []map[string]string
			for id, rule := range f.rules {
				if rule["value"] == v {
					out = append(out, map[string]string{"id": id, "notes": rule["notes"]})
				}
			}
			b, _ := json.Marshal(map[string]any{"success": true, "result": out})
			w.Write(b)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, base+"/"):
			id := strings.TrimPrefix(r.URL.Path, base+"/")
			if _, ok := f.rules[id]; !ok {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"success":false}`)
				return
			}
			delete(f.rules, id)
			fmt.Fprint(w, `{"success":true}`)
		default:
			w.WriteHeader(404)
		}
	})
}

func withCloudflare(t *testing.T, state string) (*Server, *fakeCF, *[][]string) {
	f := &fakeCF{rules: map[string]map[string]string{}}
	srv := httptest.NewTLSServer(f.handler(t))
	t.Cleanup(srv.Close)
	s, calls := newTestServer(t, state)
	s.Backends = append(s.Backends, &CloudflareBackend{ZoneID: "z1", Token: "tok", Base: srv.URL, Client: srv.Client()})
	return s, f, calls
}

func TestCloudflareBlockExtendUnblock(t *testing.T) {
	s, f, nft := withCloudflare(t, "")
	if r := s.Do(RoleAdmin, Request{Op: "block", IP: "203.0.113.5", Reason: "scanner"}); !r.OK {
		t.Fatal(r.Error)
	}
	if len(f.rules) != 1 || f.rules["r1"]["target"] != "ip" || !strings.HasPrefix(f.rules["r1"]["notes"], cfNotePrefix) {
		t.Fatalf("%+v", f.rules)
	}
	if len(*nft) != 1 {
		t.Fatalf("nftables not used too: %q", *nft)
	}
	// Extending does not create a second rule.
	s.Do(RoleAdmin, Request{Op: "block", IP: "203.0.113.5", Reason: "again", TTL: 5 * time.Hour})
	if len(f.rules) != 1 {
		t.Fatalf("duplicate rule: %+v", f.rules)
	}
	if r := s.Do(RoleAdmin, Request{Op: "unblock", IP: "203.0.113.5", Reason: "fp"}); !r.OK {
		t.Fatal(r.Error)
	}
	if len(f.rules) != 0 {
		t.Fatalf("rule not deleted: %+v", f.rules)
	}
	// IPv6 uses the ip6 target.
	s.Do(RoleAdmin, Request{Op: "block", IP: "2001:db8:1::5", Reason: "x"})
	for _, r := range f.rules {
		if r["target"] != "ip6" {
			t.Fatalf("%+v", r)
		}
	}
}

func TestCloudflareRulesAreRemovedWhenExpired(t *testing.T) {
	state := filepath.Join(t.TempDir(), "blocks.json")
	s, f, _ := withCloudflare(t, state)
	s.Do(RoleAdmin, Request{Op: "block", IP: "203.0.113.5", Reason: "x"})
	s.Do(RoleAdmin, Request{Op: "block", IP: "203.0.113.6", Reason: "y"})
	// Time passes (the enforcer was down while both expired).
	s.mu.Lock()
	for k, b := range s.blocks {
		b.Expires = time.Now().Add(-time.Minute)
		s.blocks[k] = b
	}
	s.saveState()
	s.mu.Unlock()

	s2, _, _ := withCloudflare(t, state)
	s2.Backends[1] = s.Backends[1] // same fake API
	if err := s2.LoadState(); err != nil {
		t.Fatal(err)
	}
	if len(s2.Do(RoleAdmin, Request{Op: "list"}).Blocks) != 2 {
		t.Fatal("expired remote blocks dropped before their rules were removed")
	}
	s2.mu.Lock()
	s2.sweepExpired()
	s2.mu.Unlock()
	if len(f.rules) != 0 || len(s2.Do(RoleAdmin, Request{Op: "list"}).Blocks) != 0 {
		t.Fatalf("rules left behind: %+v", f.rules)
	}
}

func TestCloudflareNeverDeletesSomeoneElsesRule(t *testing.T) {
	s, f, _ := withCloudflare(t, "")
	f.rules["manual"] = map[string]string{"value": "203.0.113.5", "notes": "blocked by the SOC team"}
	if r := s.Do(RoleAdmin, Request{Op: "block", IP: "203.0.113.5", Reason: "x"}); !r.OK {
		t.Fatal(r.Error)
	}
	s.Do(RoleAdmin, Request{Op: "unblock", IP: "203.0.113.5", Reason: "x"})
	if _, ok := f.rules["manual"]; !ok {
		t.Fatal("deleted a rule nethergate did not create")
	}
}

func TestPartialBackendFailureKeepsWhatWorked(t *testing.T) {
	s, f, nft := withCloudflare(t, "")
	f.failAll = true
	r := s.Do(RoleAdmin, Request{Op: "block", IP: "203.0.113.5", Reason: "x"})
	if r.OK || !strings.Contains(r.Error, "cloudflare") {
		t.Fatalf("failure not reported: %+v", r)
	}
	bl := s.Do(RoleAdmin, Request{Op: "list"}).Blocks
	if len(bl) != 1 || bl[0].Refs["nftables"] == "" || bl[0].Refs["cloudflare"] != "" || len(*nft) != 1 {
		t.Fatalf("local block not kept: %+v", bl)
	}
	// Once Cloudflare is back, re-blocking fills in the missing backend.
	f.failAll = false
	if r := s.Do(RoleAdmin, Request{Op: "block", IP: "203.0.113.5", Reason: "retry", TTL: 3 * time.Hour}); !r.OK {
		t.Fatal(r.Error)
	}
	if len(f.rules) != 1 {
		t.Fatalf("%+v", f.rules)
	}
}

// Package e2e runs the real nethergate binaries (enforcer, watch, mcp and
// the human CLI) against each other over the real Unix socket. nftables is
// replaced by a fake `nft` on PATH that records its arguments, so the test
// needs no privileges. Roles are UID based; the test has one UID, so each
// phase restarts the processes with a config that gives that UID the role
// under test.
package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "nethergate-e2e-bin")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "nethergate")
	out, err := exec.Command("go", "build", "-o", bin, "../cmd/nethergate").CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("build: %v\n%s", err, out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	t   *testing.T
	dir string
	uid int
}

func (e *env) path(p string) string { return filepath.Join(e.dir, p) }

func (e *env) writeConfig(name, clients string, extra ...string) {
	cfg := fmt.Sprintf(`{
  "logs": [{"path": "access.log", "format": "nginx"}],
  "state_dir": "st", "enforcer_state_dir": "est", "report_dir": "rep",
  "enforcer_socket": "e.sock",
  "enforcer_clients": %s,
  "osint": {"enabled": false},
  "audit_anchor": {"interval": "1s"},
  "policy": {"dry_run": false, "default_ttl": "1h", "max_ttl": "24h", "max_blocks_per_hour": 60,
             "quota_per_hour": {"ai": 20, "rules": 60, "playbook": 60}, "auto_block_score": 90, "ai_min_score": 30},
  "playbook": {"path": "playbook.json", "lessons_path": "lessons.json", "max_match_ips": 200}%s
}`, clients, strings.Join(append([]string{""}, extra...), ",\n  "))
	if err := os.WriteFile(e.path(name+".json"), []byte(cfg), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) log(lines ...string) {
	f, err := os.OpenFile(e.path("access.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	ts := time.Now().UTC().Format("02/Jan/2006:15:04:05 -0700")
	for _, l := range lines {
		parts := strings.SplitN(l, " ", 4) // ip status ua path
		fmt.Fprintf(f, "%s - - [%s] \"GET %s HTTP/1.1\" %s 10 \"-\" \"%s\"\n", parts[0], ts, parts[3], parts[1], parts[2])
	}
}

func (e *env) cmd(cfg string, args ...string) *exec.Cmd {
	c := exec.Command(bin, append([]string{"-config", cfg + ".json"}, args...)...)
	c.Dir = e.dir
	c.Env = append(os.Environ(), "PATH="+e.path("fakebin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"NFT_LOG="+e.path("nft.log"))
	return c
}

// start runs a daemon until the end of the phase; its stderr goes to name.log.
func (e *env) start(cfg, sub string) func() {
	c := e.cmd(cfg, sub)
	f, err := os.OpenFile(e.path(sub+".log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		e.t.Fatal(err)
	}
	c.Stderr = f
	if err := c.Start(); err != nil {
		e.t.Fatal(err)
	}
	if sub == "enforcer" {
		e.waitFor("enforcer socket", 5*time.Second, func() bool { _, err := os.Stat(e.path("e.sock")); return err == nil })
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = c.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = c.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = c.Process.Kill()
			<-done
		}
		f.Close()
		_ = os.Remove(e.path("e.sock"))
	}
	e.t.Cleanup(stop)
	return stop
}

func (e *env) run(cfg string, args ...string) (string, error) {
	out, err := e.cmd(cfg, args...).CombinedOutput()
	return string(out), err
}

func (e *env) waitFor(what string, d time.Duration, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	e.t.Fatalf("timed out waiting for %s", what)
}

func (e *env) nftLog() string {
	b, _ := os.ReadFile(e.path("nft.log"))
	return string(b)
}

// raw talks to the enforcer socket directly, as a compromised process would.
func (e *env) raw(req string) map[string]any {
	e.t.Helper()
	c, err := net.Dial("unix", "e.sock")
	if err != nil {
		e.t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintln(c, req)
	var resp map[string]any
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func (e *env) mcp(cfg string, calls ...string) []string {
	e.t.Helper()
	c := e.cmd(cfg, "mcp")
	c.Stdin = strings.NewReader(strings.Join(calls, "\n") + "\n")
	out, err := c.Output()
	if err != nil {
		e.t.Fatalf("mcp: %v", err)
	}
	var texts []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
			} `json:"result"`
		}
		_ = json.Unmarshal(sc.Bytes(), &m)
		if len(m.Result.Content) > 0 {
			texts = append(texts, m.Result.Content[0].Text)
		}
	}
	return texts
}

func toolCall(name string, args map[string]any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args}})
	return string(b)
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real daemons; takes ~30s")
	}
	dir := t.TempDir()
	t.Chdir(dir) // unix socket paths are limited to 108 bytes: use relative ones
	e := &env{t: t, dir: dir, uid: os.Getuid()}
	if err := os.MkdirAll(e.path("fakebin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.path("fakebin/nft"), []byte("#!/bin/sh\necho \"$*\" >> \"$NFT_LOG\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.writeConfig("as-watch", fmt.Sprintf(`{"watch_uids": [%d]}`, e.uid))
	e.writeConfig("as-mcp", fmt.Sprintf(`{"mcp_uids": [%d]}`, e.uid))
	e.writeConfig("as-admin", fmt.Sprintf(`{"admin_uids": [%d]}`, e.uid))
	_ = os.WriteFile(e.path("playbook.json"), []byte("[]"), 0o644)

	attacker, visitor := "203.0.113.5", "198.51.100.7"
	e.log(visitor+" 200 Mozilla/5.0 /", visitor+" 200 Mozilla/5.0 /about")

	t.Run("rule engine blocks the attacker, not the visitor", func(t *testing.T) {
		stopE := e.start("as-watch", "enforcer")
		stopW := e.start("as-watch", "watch")
		e.log(attacker+" 404 sqlmap/1.8 /.env", attacker+" 404 sqlmap/1.8 /.git/config",
			attacker+" 404 sqlmap/1.8 /?id=1%27%20union%20select%201", attacker+" 404 sqlmap/1.8 /../../etc/passwd")
		e.waitFor("auto-block of the attacker", 20*time.Second, func() bool { return strings.Contains(e.nftLog(), attacker+" timeout") })
		if strings.Contains(e.nftLog(), visitor) {
			t.Fatalf("visitor blocked:\n%s", e.nftLog())
		}
		// A request cannot name its own actor; the forged field is ignored.
		if r := e.raw(`{"op":"block","ip":"` + visitor + `","reason":"x","actor":"human"}`); r["ok"] == true {
			t.Fatalf("forged actor accepted: %v", r)
		}
		stopW()
		stopE()
	})

	t.Run("a compromised AI process is contained by the enforcer", func(t *testing.T) {
		stop := e.start("as-mcp", "enforcer")
		defer stop()
		if r := e.raw(`{"op":"block","ip":"` + visitor + `","reason":"trust me"}`); r["ok"] == true {
			t.Fatalf("ai blocked a bystander: %v", r)
		}
		if r := e.raw(`{"op":"unblock","ip":"` + attacker + `","reason":"fp"}`); r["ok"] == true || !strings.Contains(fmt.Sprint(r["error"]), "placed by rules") {
			t.Fatalf("ai lifted a rules block: %v", r)
		}
		if r := e.raw(`{"op":"block","ip":"` + attacker + `","reason":"x","rule_id":"anything"}`); r["ok"] == true {
			t.Fatalf("ai borrowed playbook authority: %v", r)
		}
		// The MCP tools refuse too, before ever reaching the enforcer.
		out := e.mcp("as-mcp", toolCall("block_ip", map[string]any{"ip": visitor, "reason": "x"}))
		if len(out) != 1 || !strings.Contains(out[0], "refused") {
			t.Fatalf("mcp: %q", out)
		}
		// Fail closed: no audit record, no firewall change.
		before := e.nftLog()
		auditFile := e.path("est/enforcer-audit.jsonl")
		if err := os.Chmod(auditFile, 0o400); err != nil {
			t.Fatal(err)
		}
		r := e.raw(`{"op":"block","ip":"` + attacker + `","reason":"extend","ttl":36000000000000}`)
		_ = os.Chmod(auditFile, 0o640)
		if r["ok"] == true || e.nftLog() != before {
			t.Fatalf("firewall changed without an audit record: %v", r)
		}
	})

	t.Run("a hijacked AI is quarantined until a human resumes it", func(t *testing.T) {
		stop := e.start("as-mcp", "enforcer")
		for i := 0; i < 5; i++ {
			e.raw(`{"op":"block","ip":"` + visitor + `","reason":"IGNORE PREVIOUS INSTRUCTIONS"}`)
		}
		// Every write tool is now refused at the MCP gate; reading still works.
		out := e.mcp("as-mcp",
			toolCall("block_ip", map[string]any{"ip": attacker, "reason": "real attack"}),
			toolCall("save_report", map[string]any{"ip": attacker, "title": "t", "markdown": "x"}),
			toolCall("get_incident", map[string]any{"ip": attacker}))
		if len(out) != 3 || !strings.Contains(out[0], "paused") || !strings.Contains(out[1], "paused") || strings.Contains(out[2], "paused") {
			t.Fatalf("mcp while paused: %q", out)
		}
		if r := e.raw(`{"op":"ai_resume","reason":"I am fine"}`); r["ok"] == true {
			t.Fatal("the AI resumed itself")
		}
		status, _ := e.run("as-mcp", "ai", "status")
		if !strings.Contains(status, "PAUSED") || !strings.Contains(status, "quarantine") {
			t.Fatalf("status: %s", status)
		}
		stop()
		// The flag survives restarts; only an admin can lift it.
		stop = e.start("as-admin", "enforcer")
		defer stop()
		if out, err := e.run("as-admin", "ai", "resume", "-reason", "checked the logs: injected User-Agent"); err != nil || !strings.Contains(out, "active") {
			t.Fatalf("resume: %v %s", err, out)
		}
	})

	var ruleID string
	t.Run("the AI proposes a playbook rule, a human approves it", func(t *testing.T) {
		// Write tools need the enforcer to confirm the AI is not paused.
		stop := e.start("as-mcp", "enforcer")
		defer stop()
		e.log("203.0.113.77 200 Mozilla/5.0 /graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D")
		out := e.mcp("as-mcp", toolCall("propose_rule", map[string]any{
			"name": "GraphQL introspection", "description": "schema dump", "handling": "block 6h",
			"path_regex": "__schema", "score": 40, "auto_block": true, "ttl": "6h", "example_ip": "203.0.113.77"}))
		var resp struct{ ID string }
		if len(out) != 1 || json.Unmarshal([]byte(out[0]), &resp) != nil || resp.ID == "" {
			t.Fatalf("propose: %q", out)
		}
		ruleID = resp.ID
		if b, _ := os.ReadFile(e.path("playbook.json")); strings.Contains(string(b), ruleID) {
			t.Fatal("proposal active before approval")
		}
		if out, err := e.run("as-admin", "playbook", "approve", ruleID); err != nil {
			t.Fatalf("approve: %v\n%s", err, out)
		}
	})

	t.Run("an approved rule blocks the next occurrence instantly", func(t *testing.T) {
		stopE := e.start("as-watch", "enforcer")
		stopW := e.start("as-watch", "watch")
		e.log("203.0.113.88 200 Mozilla/5.0 /graphql?query={__schema{queryType{name}}}")
		e.waitFor("playbook block", 20*time.Second, func() bool { return strings.Contains(e.nftLog(), "203.0.113.88 timeout 21600s") })
		stopW()
		stopE()
	})

	t.Run("a human corrects a wrong block and it is remembered", func(t *testing.T) {
		stop := e.start("as-admin", "enforcer")
		defer stop()
		out, err := e.run("as-admin", "correct", "203.0.113.88", "benign", "-note", "partner A's GraphQL tooling")
		if err != nil {
			t.Fatalf("correct: %v\n%s", err, out)
		}
		if !strings.Contains(e.nftLog(), "delete element inet nethergate block4 { 203.0.113.88 }") {
			t.Fatalf("block not lifted:\n%s", e.nftLog())
		}
		lessons, _ := os.ReadFile(e.path("lessons.json"))
		if !strings.Contains(string(lessons), "partner A") || !strings.Contains(string(lessons), ruleID) {
			t.Fatalf("lesson not recorded with the rule involved: %s", lessons)
		}
		// The AI now sees the lesson and the allow rule protects the partner.
		if r := e.raw(`{"op":"block","ip":"203.0.113.88","reason":"x"}`); r["ok"] == true {
			t.Fatal("allowlisted partner blocked")
		}
	})

	// A plaintext syslog relay on loopback stands in for the SIEM.
	siem, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer siem.Close()
	received := make(chan string, 4096)
	go func() {
		for {
			c, err := siem.Accept()
			if err != nil {
				return
			}
			go func() {
				r := bufio.NewReader(c)
				for {
					lenStr, err := r.ReadString(' ')
					if err != nil {
						return
					}
					n, _ := strconv.Atoi(strings.TrimSpace(lenStr))
					buf := make([]byte, n)
					if _, err := io.ReadFull(r, buf); err != nil {
						return
					}
					received <- string(buf)
				}
			}()
		}
	}()
	metricsLn, _ := net.Listen("tcp", "127.0.0.1:0")
	metricsAddr := metricsLn.Addr().String()
	metricsLn.Close()
	e.writeConfig("as-watch-obs", fmt.Sprintf(`{"watch_uids": [%d]}`, e.uid),
		fmt.Sprintf(`"forward": {"interval": "1s", "syslog": {"address": %q, "plaintext": true}}`, siem.Addr().String()),
		fmt.Sprintf(`"metrics": {"listen": %q}`, metricsAddr))
	var siemLog strings.Builder
	waitSIEM := func(what string, cond func(string) bool) {
		e.waitFor(what, 15*time.Second, func() bool {
			for {
				select {
				case m := <-received:
					siemLog.WriteString(m + "\n")
				default:
					return cond(siemLog.String())
				}
			}
		})
	}

	t.Run("audit records reach the SIEM and metrics are exported", func(t *testing.T) {
		stopE := e.start("as-watch-obs", "enforcer")
		stopW := e.start("as-watch-obs", "watch")
		waitSIEM("enforcer audit records at the SIEM", func(s string) bool {
			return strings.Contains(s, `"file":"enforcer-audit.jsonl"`) && strings.Contains(s, " anchor - ")
		})
		// Counters live in each process: produce a refusal and an audit
		// failure in this enforcer so the metrics have something to show.
		e.raw(`{"op":"block","ip":"` + visitor + `","reason":"no incident"}`)
		auditFile := e.path("est/enforcer-audit.jsonl")
		_ = os.Chmod(auditFile, 0o400)
		e.raw(`{"op":"block","ip":"` + attacker + `","reason":"extend","ttl":72000000000000}`)
		_ = os.Chmod(auditFile, 0o640)
		var body string
		e.waitFor("metrics endpoint", 10*time.Second, func() bool {
			resp, err := http.Get("http://" + metricsAddr + "/metrics")
			if err != nil {
				return false
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(b)
			return strings.Contains(body, "nethergate_enforcer_up 1")
		})
		for _, want := range []string{
			`nethergate_enforcer_requests_total{actor="rules",op="block",result="ok"}`,
			`nethergate_enforcer_requests_total{actor="rules",op="block",result="rejected"} 1`,
			`nethergate_enforcer_requests_total{actor="rules",op="block",result="error"} 1`,
			`nethergate_enforcer_audit_write_failures_total 1`,
			`nethergate_enforcer_quota_remaining{actor="ai"}`,
			`nethergate_playbook_rules{verdict="allow"} 1`,
			`nethergate_audit_records{file="enforcer-audit.jsonl"}`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("metrics missing %s", want)
			}
		}
		stopW()
		stopE()
	})

	t.Run("audit logs verify, and truncation is caught by the anchors", func(t *testing.T) {
		if out, err := e.run("as-admin", "verify"); err != nil {
			t.Fatalf("verify: %v\n%s", err, out)
		}
		var anchors strings.Builder
		for _, f := range []string{"enforcer.log", "watch.log"} {
			b, _ := os.ReadFile(e.path(f))
			anchors.Write(b)
		}
		if err := os.WriteFile(e.path("anchors.txt"), []byte(anchors.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := e.run("as-admin", "verify", "-anchors", "anchors.txt"); err != nil {
			t.Fatalf("verify -anchors: %v\n%s", err, out)
		}
		p := e.path("est/enforcer-audit.jsonl")
		b, _ := os.ReadFile(p)
		lines := strings.SplitAfter(string(b), "\n")
		_ = os.WriteFile(p, []byte(strings.Join(lines[:2], "")), 0o640)
		if out, err := e.run("as-admin", "verify"); err != nil {
			t.Fatalf("a truncated chain still self-verifies, expected ok: %s", out)
		}
		out, err := e.run("as-admin", "verify", "-anchors", "anchors.txt")
		if err == nil || !strings.Contains(out, "TAMPERED") {
			t.Fatalf("truncation not detected:\n%s", out)
		}
		// The forwarder notices too, and tells the SIEM right away.
		stopW := e.start("as-watch-obs", "watch")
		defer stopW()
		waitSIEM("tamper event at the SIEM", func(s string) bool {
			return strings.Contains(s, " tamper - ") && strings.Contains(s, "enforcer-audit.jsonl")
		})
	})
}

package mcp

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michitaka/nethergate/internal/playbook"
)

func propose(t *testing.T, s *Server, args map[string]any) (string, bool) {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "propose_rule", "arguments": args}})
	return text(call(t, s, string(b))[0])
}

func base(extra map[string]any) map[string]any {
	m := map[string]any{"name": "graphql introspection", "description": "schema dump before targeted queries",
		"handling": "blocked 6h; no data exposed", "score": 40, "example_ip": "203.0.113.77"}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestProposeRuleRejectsUnsafeRules(t *testing.T) {
	s, _ := setup(t)
	cases := map[string]map[string]any{
		"matches everything":   {"path_regex": ".*"},
		"matches normal pages": {"path_regex": "^/"},
		"matches browsers":     {"ua_regex": "Mozilla"},
		"misses example ip":    {"path_regex": "wp-json"},
		"hits normal readers":  {"path_regex": "(__schema|^/articles/)"},
		"bad regex":            {"path_regex": "(unclosed"},
		"score too high":       {"path_regex": "__schema", "score": 99},
	}
	for name, extra := range cases {
		msg, isErr := propose(t, s, base(extra))
		t.Logf("%s: %s", name, msg)
		if !isErr {
			t.Errorf("%s: accepted: %s", name, msg)
		}
	}
	if rules, _ := playbook.Load(s.Cfg.ProposalsPath()); len(rules) != 0 {
		t.Fatalf("rejected rules were stored: %d", len(rules))
	}
}

func TestProposeRuleIsPendingUntilApproved(t *testing.T) {
	s, _ := setup(t)
	msg, isErr := propose(t, s, base(map[string]any{"path_regex": "__schema", "auto_block": true, "ttl": "6h"}))
	if isErr || !strings.Contains(msg, "pending human approval") {
		t.Fatalf("%s", msg)
	}
	if _, isErr := propose(t, s, base(map[string]any{"path_regex": "__schema", "auto_block": true, "ttl": "6h"})); !isErr {
		t.Error("duplicate accepted")
	}
	pending, _ := playbook.Load(s.Cfg.ProposalsPath())
	if len(pending) != 1 || pending[0].CreatedBy != "ai" || pending[0].ApprovedAt != nil {
		t.Fatalf("%+v", pending)
	}
	// Not approved: the analyzer the AI sees has no such rule active.
	if len(s.Rules) != 0 {
		t.Fatal("proposal became active without approval")
	}
	res := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_playbook","arguments":{}}}`)
	if txt, _ := text(res[0]); !strings.Contains(txt, "pending_approval") || !strings.Contains(txt, "__schema") {
		t.Fatalf("%s", txt)
	}
}

func callTool(t *testing.T, s *Server, name string, args map[string]any) (string, bool) {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args}})
	return text(call(t, s, string(b))[0])
}

func TestHumanReviewQueueAndLessons(t *testing.T) {
	s, _ := setup(t)
	s.Cfg.Playbook.LessonsPath = filepath.Join(t.TempDir(), "lessons.json")
	q := map[string]any{"ip": "203.0.113.77", "question": "customer integration or attack?", "considered": "200s only", "leaning": "unsure"}
	if msg, isErr := callTool(t, s, "request_human_review", q); isErr {
		t.Fatal(msg)
	}
	q["question"] = "updated question"
	callTool(t, s, "request_human_review", q)
	reviews, _ := playbook.LoadList[playbook.Review](s.Cfg.ReviewsPath())
	if len(reviews) != 1 || reviews[0].Question != "updated question" {
		t.Fatalf("one open review per IP expected: %+v", reviews)
	}
	if _, isErr := callTool(t, s, "request_human_review", map[string]any{"ip": "1.1.1.1", "question": "x", "considered": "x", "leaning": "unsure"}); !isErr {
		t.Error("review for an IP with no activity accepted")
	}
	// A human answered earlier: the AI must see it with the incident.
	playbook.UpdateList(s.Cfg.Playbook.LessonsPath, 0o600, func(l []playbook.Lesson) ([]playbook.Lesson, error) {
		return append(l, playbook.Lesson{IP: "203.0.113.77", Verdict: "benign", Note: "partner's GraphQL client"}), nil
	})
	txt, _ := callTool(t, s, "get_incident", map[string]any{"ip": "203.0.113.77"})
	if !strings.Contains(txt, "partner's GraphQL client") || !strings.Contains(txt, "open_review") {
		t.Fatalf("%s", txt)
	}
}

func TestProposeAllowRuleShowsWhatItWouldExempt(t *testing.T) {
	s, _ := setup(t)
	msg, isErr := callTool(t, s, "propose_rule", map[string]any{"name": "pentest vendor", "description": "contracted scan",
		"handling": "do not block", "verdict": "allow", "ip_prefixes": []string{"203.0.113.0/28"}, "score": 0, "example_ip": "203.0.113.5"})
	if isErr || !strings.Contains(msg, "suspicious_ips_it_would_exempt") || !strings.Contains(msg, "203.0.113.5 (score") {
		t.Fatalf("%s", msg)
	}
}

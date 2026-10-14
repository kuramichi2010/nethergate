package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/detect"
	"github.com/kuramichi2010/nethergate/internal/playbook"
)

const maxPending = 100

func (s *Server) playbookTools() []tool {
	return []tool{
		{"list_playbook", "Show the playbook: approved rules for attack patterns handled before (with how they were handled), and rules proposed by the AI that are waiting for human approval.",
			obj(map[string]any{}), s.listPlaybook},
		{"propose_rule", "Record a special attack pattern you just handled so it is recognised instantly next time. " +
			"The rule is checked against ordinary traffic and the current logs, then waits for a human to approve it; it has no effect until then. " +
			"Use narrow regexes (Go RE2 syntax) that match the attack, not normal users.",
			obj(map[string]any{
				"name":           str("short name of the pattern"),
				"description":    str("what the attack is and how to recognise it"),
				"handling":       str("what you did and what to do next time"),
				"path_regex":     str("regex on the URL-decoded request path"),
				"ua_regex":       str("regex on the User-Agent"),
				"ssh_user_regex": str("regex on usernames in failed SSH logins (not combinable with HTTP fields)"),
				"verdict":        map[string]any{"type": "string", "enum": []string{"malicious", "allow"}, "description": "malicious (default) or allow: an exception for traffic that looked suspicious but is legitimate"},
				"ip_prefixes":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "allow rules only: source ranges, e.g. a partner's scanner"},
				"min_hits":       map[string]any{"type": "integer", "minimum": 1, "maximum": 10000, "description": "matching events from one source before the rule triggers (default 1)"},
				"score":          map[string]any{"type": "integer", "minimum": 0, "maximum": playbook.MaxScore, "description": "added to the incident score when triggered"},
				"auto_block":     map[string]any{"type": "boolean", "description": "block immediately on trigger, without AI triage"},
				"ttl":            str("block duration for auto_block, e.g. 6h (capped by policy)"),
				"example_ip":     str("an IP from the current logs that this rule must match"),
			}, "name", "description", "handling", "score", "example_ip"), s.proposeRule},
		{"request_human_review", "Use when you cannot decide confidently whether a source is an attack (e.g. it could be a customer, a partner's scanner, our own monitoring). " +
			"Do not block on a guess: queue the case for a human instead. Their answer is remembered as a lesson and shown to you next time.",
			obj(map[string]any{
				"ip":             str("source IP"),
				"question":       str("what exactly you need the human to decide"),
				"considered":     str("evidence for and against, briefly"),
				"leaning":        map[string]any{"type": "string", "enum": []string{"malicious", "benign", "unsure"}},
				"interim_action": str("what you did meanwhile, e.g. 'nothing, watching' or 'blocked 15m'"),
			}, "ip", "question", "considered", "leaning"), s.requestReview},
	}
}

func (s *Server) listPlaybook(ctx context.Context, _ json.RawMessage) (any, error) {
	pending, errs := playbook.Load(s.Cfg.ProposalsPath())
	out := map[string]any{"approved": nonNil(s.Rules), "pending_approval": nonNil(pending)}
	if len(errs) > 0 {
		out["pending_errors"] = len(errs)
	}
	lessons, err := playbook.LoadList[playbook.Lesson](s.Cfg.Playbook.LessonsPath)
	if err != nil {
		out["lessons_error"] = err.Error()
	}
	if len(lessons) > 30 {
		lessons = lessons[len(lessons)-30:]
	}
	out["recent_human_lessons"] = lessons
	reviews, _ := playbook.LoadList[playbook.Review](s.Cfg.ReviewsPath())
	out["reviews_waiting_for_human"] = len(reviews)
	return out, nil
}

func nonNil(r []*playbook.Rule) []*playbook.Rule {
	if r == nil {
		return []*playbook.Rule{}
	}
	return r
}

// cleanText keeps newlines but removes other control and format characters.
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, ""))
}

// Replay is what a candidate rule would have done over the current window.
type Replay struct {
	MatchedIPs    int `json:"matched_ips"`
	TriggeredIPs  int `json:"triggered_ips"`
	NormalLooking int `json:"normal_looking_ips,omitempty"`
	// Allow rules: sources that look suspicious today and would be exempted.
	SuspiciousExempted []string `json:"suspicious_ips_it_would_exempt,omitempty"`
	Examples           []string `json:"example_ips"`
}

// ReplayRule runs the logs again with r added and reports who it matches.
// For a malicious rule, "normal looking" sources had no other signal and
// mostly successful requests: matching them suggests it would hit real
// users. For an allow rule, it lists sources that currently score as
// suspicious and would no longer be acted on, so a human sees the cost.
func ReplayRule(scan func([]*playbook.Rule) (*detect.Analyzer, error), approved []*playbook.Rule, r *playbook.Rule, window time.Duration) (Replay, *detect.Analyzer, error) {
	a, err := scan(append(append([]*playbook.Rule(nil), approved...), r))
	if err != nil {
		return Replay{}, nil, err
	}
	var before *detect.Analyzer
	if r.IsAllow() {
		if before, err = scan(approved); err != nil {
			return Replay{}, nil, err
		}
	}
	var rep Replay
	for _, inc := range a.Incidents(time.Now().Add(-window), 0) {
		n, triggered := inc.Hits(r)
		if n == 0 {
			continue
		}
		rep.MatchedIPs++
		if triggered {
			rep.TriggeredIPs++
		}
		if len(rep.Examples) < 10 {
			rep.Examples = append(rep.Examples, inc.IP.String())
		}
		if r.IsAllow() {
			if b := before.Get(inc.IP); b != nil && b.Score >= 25 && len(rep.SuspiciousExempted) < 20 {
				rep.SuspiciousExempted = append(rep.SuspiciousExempted, fmt.Sprintf("%s (score %d: %s)", inc.IP, b.Score, b.Actor.Type))
			}
			continue
		}
		// Only this rule's own label, and mostly 2xx/3xx responses.
		if len(inc.Categories) == 0 && inc.SSHFails == 0 && (inc.Requests == 0 || inc.Errors4xx*100/inc.Requests < 20) {
			rep.NormalLooking++
		}
	}
	return rep, a, nil
}

func (s *Server) proposeRule(ctx context.Context, raw json.RawMessage) (any, error) {
	var p struct {
		Name, Description, Handling string
		PathRegex                   string   `json:"path_regex"`
		UARegex                     string   `json:"ua_regex"`
		SSHUserRegex                string   `json:"ssh_user_regex"`
		MinHits                     int      `json:"min_hits"`
		Score                       int      `json:"score"`
		AutoBlock                   bool     `json:"auto_block"`
		TTL                         string   `json:"ttl"`
		ExampleIP                   string   `json:"example_ip"`
		Verdict                     string   `json:"verdict"`
		IPPrefixes                  []string `json:"ip_prefixes"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, err
	}
	ip, err := parseIP(p.ExampleIP)
	if err != nil {
		return nil, err
	}
	r := &playbook.Rule{
		ID: playbook.NewID(), Name: cleanText(p.Name), Description: cleanText(p.Description), Handling: cleanText(p.Handling),
		Verdict:   p.Verdict,
		Match:     playbook.Match{PathRegex: p.PathRegex, UARegex: p.UARegex, SSHUserRegex: p.SSHUserRegex, MinHits: p.MinHits, IPPrefixes: p.IPPrefixes},
		Score:     p.Score,
		AutoBlock: p.AutoBlock, ExampleIP: ip.String(), CreatedBy: "ai", CreatedAt: time.Now().UTC(),
	}
	if p.TTL != "" {
		d, err := time.ParseDuration(p.TTL)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("invalid ttl")
		}
		r.TTL = config.Duration(min(d, s.Cfg.Policy.MaxTTL.D()))
	}
	if err := r.Compile(); err != nil {
		return nil, err
	}
	if err := r.CheckBenign(); err != nil {
		return nil, err
	}
	rep, a, err := ReplayRule(s.Scan, s.Rules, r, s.Cfg.Window.D())
	if err != nil {
		return nil, err
	}
	inc := a.Get(ip)
	matchedExample := false
	if inc != nil {
		n, _ := inc.Hits(r)
		matchedExample = n > 0
	}
	if !matchedExample {
		return nil, fmt.Errorf("the rule does not match any activity from example_ip %s in the current logs", ip)
	}
	if rep.MatchedIPs > s.Cfg.Playbook.MaxMatchIPs {
		return nil, fmt.Errorf("too broad: matches %d source IPs (limit %d)", rep.MatchedIPs, s.Cfg.Playbook.MaxMatchIPs)
	}
	if rep.NormalLooking > 2 {
		return nil, fmt.Errorf("too broad: matches %d sources whose traffic otherwise looks normal (e.g. %v)", rep.NormalLooking, rep.Examples)
	}
	err = playbook.Update(s.Cfg.ProposalsPath(), 0o660, func(rules []*playbook.Rule) ([]*playbook.Rule, error) {
		if len(rules) >= maxPending {
			return nil, fmt.Errorf("%d proposals are already waiting; ask a human to review them", len(rules))
		}
		for _, o := range append(rules, s.Rules...) {
			if o.Match.Key() == r.Match.Key() {
				return nil, fmt.Errorf("an identical rule already exists (%s)", o.ID)
			}
		}
		return append(rules, r), nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":      r.ID,
		"status":  "pending human approval (no effect until approved)",
		"replay":  rep,
		"approve": "sudo nethergate playbook approve " + r.ID,
	}, nil
}

func (s *Server) requestReview(ctx context.Context, raw json.RawMessage) (any, error) {
	var p struct {
		IP, Question, Considered, Leaning string
		Interim                           string `json:"interim_action"`
	}
	if err := decode(raw, &p); err != nil {
		return nil, err
	}
	ip, err := parseIP(p.IP)
	if err != nil {
		return nil, err
	}
	switch p.Leaning {
	case "malicious", "benign", "unsure":
	default:
		return nil, fmt.Errorf("leaning must be malicious, benign or unsure")
	}
	if len(p.Question)+len(p.Considered)+len(p.Interim) > 3*playbook.MaxText {
		return nil, fmt.Errorf("too long")
	}
	a, err := s.analyzer()
	if err != nil {
		return nil, err
	}
	inc := a.Get(ip)
	if inc == nil {
		return nil, fmt.Errorf("no activity from %s in the current window", ip)
	}
	rv := playbook.Review{ID: playbook.NewID(), CreatedAt: time.Now().UTC(), IP: ip.String(), Score: inc.Score,
		Question: cleanText(p.Question), Considered: cleanText(p.Considered), Leaning: p.Leaning, Interim: cleanText(p.Interim)}
	err = playbook.UpdateList(s.Cfg.ReviewsPath(), 0o660, func(list []playbook.Review) ([]playbook.Review, error) {
		for i, o := range list {
			if o.IP == rv.IP { // one open question per IP: refresh it
				rv.ID = o.ID
				list[i] = rv
				return list, nil
			}
		}
		if len(list) >= playbook.MaxReviews {
			return nil, fmt.Errorf("%d reviews are already waiting for a human", len(list))
		}
		return append(list, rv), nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"review_id": rv.ID, "status": "queued for a human; the administrators are notified",
		"human_command": "nethergate review answer " + rv.ID + " malicious|benign -note \"...\""}, nil
}

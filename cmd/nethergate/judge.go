package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kuramichi2010/nethergate/internal/audit"
	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/enforce"
	"github.com/kuramichi2010/nethergate/internal/playbook"
	"github.com/kuramichi2010/nethergate/internal/policy"
	"github.com/kuramichi2010/nethergate/internal/watch"
)

const judgeUsage = `usage: nethergate review list
       nethergate review answer <review-id> malicious|benign -note "..." [options]
       nethergate correct <ip> malicious|benign -note "..." [options]

  benign:    lifts the block, adds an allow rule for the IP (or -allow-prefix), records the lesson
  malicious: blocks the IP (-ttl), optionally records a pattern rule, records the lesson
options:
  -note text           why (required): this is what nethergate and the AI will remember
  -ttl 6h              block duration for malicious
  -allow-prefix cidr   benign: allow this range instead of the single IP (repeatable, comma separated)
  -no-allow            benign: record the lesson and unblock, but add no allow rule
  -path-regex / -ua-regex / -ssh-user-regex
                       malicious: also record a pattern rule; benign: narrow the allow rule to this pattern
  -auto-block          malicious pattern rule blocks instantly next time
  -remove-rules        remove the playbook rules that caused the wrong decision`

func runReview(cfg *config.Config, args []string) error {
	if len(args) == 1 && args[0] == "list" {
		reviews, err := playbook.LoadList[playbook.Review](cfg.ReviewsPath())
		if err != nil {
			return err
		}
		if len(reviews) == 0 {
			fmt.Println("no open reviews")
			return nil
		}
		for _, r := range reviews {
			fmt.Printf("[%s] %s  ip=%s score=%d  AI leaning: %s\n  Q: %s\n  considered: %s\n  meanwhile: %s\n\n",
				r.ID, r.CreatedAt.Local().Format("2006-01-02 15:04"), r.IP, r.Score, r.Leaning, r.Question, r.Considered, r.Interim)
		}
		return nil
	}
	if len(args) >= 3 && args[0] == "answer" {
		reviews, err := playbook.LoadList[playbook.Review](cfg.ReviewsPath())
		if err != nil {
			return err
		}
		for _, r := range reviews {
			if r.ID == args[1] {
				return judge(cfg, r.IP, args[2], args[3:], &r)
			}
		}
		return fmt.Errorf("no open review %s", args[1])
	}
	return errors.New(judgeUsage)
}

func runCorrect(cfg *config.Config, args []string) error {
	if len(args) < 2 {
		return errors.New(judgeUsage)
	}
	return judge(cfg, args[0], args[1], args[2:], nil)
}

func judge(cfg *config.Config, ipStr, verdict string, rest []string, review *playbook.Review) error {
	fs := flag.NewFlagSet("judge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	note := fs.String("note", "", "")
	ttl := fs.Duration("ttl", cfg.Policy.DefaultTTL.D(), "")
	allowPrefix := fs.String("allow-prefix", "", "")
	noAllow := fs.Bool("no-allow", false, "")
	pathRe := fs.String("path-regex", "", "")
	uaRe := fs.String("ua-regex", "", "")
	sshRe := fs.String("ssh-user-regex", "", "")
	autoBlock := fs.Bool("auto-block", false, "")
	removeRules := fs.Bool("remove-rules", false, "")
	if err := fs.Parse(rest); err != nil || fs.NArg() > 0 {
		return errors.New(judgeUsage)
	}
	if verdict != "malicious" && verdict != "benign" {
		return errors.New("verdict must be malicious or benign")
	}
	if strings.TrimSpace(*note) == "" {
		return errors.New("-note is required: it is the lesson that will be remembered")
	}
	ip, err := policy.ParseAddr(ipStr)
	if err != nil {
		return err
	}
	key := ip.String()
	now := time.Now().UTC()
	by := "human:" + currentUser()
	lesson := playbook.Lesson{ID: playbook.NewID(), Time: now, By: by, IP: key, Verdict: verdict, Note: *note, Kind: "correction"}
	if review != nil {
		lesson.Kind, lesson.ReviewID, lesson.Question = "review_answer", review.ID, review.Question
	}

	// What did nethergate do, and which rules were behind it?
	approved, errs := playbook.Load(cfg.Playbook.Path)
	if len(errs) > 0 {
		return fmt.Errorf("fix the playbook first: %w", errors.Join(errs...))
	}
	if resp, err := enforce.Call(cfg.EnforcerSocket, enforce.Request{Op: "list"}); err == nil {
		for _, b := range resp.Blocks {
			if b.IP == key {
				lesson.PriorAction = fmt.Sprintf("blocked by %s until %s: %s", b.Actor, b.Expires.Format(time.RFC3339), b.Reason)
			}
		}
	}
	if lesson.PriorAction == "" {
		lesson.PriorAction = "not blocked"
	}
	var involved []*playbook.Rule
	if a, err := watch.Scan(cfg, approved, time.Now()); err == nil {
		if inc := a.Get(ip); inc != nil {
			for _, r := range approved {
				// benign: malicious rules that fired wrongly; malicious: allow rules that hid it
				if n, trig := inc.Hits(r); n > 0 && (trig || r.IsAllow()) && r.IsAllow() == (verdict == "malicious") {
					involved = append(involved, r)
					lesson.RulesInvolved = append(lesson.RulesInvolved, r.ID+" ("+r.Name+")")
				}
			}
		}
	}
	// Allow rules matched by IP range alone never show up as hits when the
	// IP has no activity in the window; catch them for malicious verdicts.
	if verdict == "malicious" {
		for _, r := range approved {
			for _, p := range r.Prefixes() {
				if p.Contains(ip) && !containsRule(involved, r) {
					involved = append(involved, r)
					lesson.RulesInvolved = append(lesson.RulesInvolved, r.ID+" ("+r.Name+")")
				}
			}
		}
	}

	if *removeRules && len(involved) > 0 {
		err := playbook.Update(cfg.Playbook.Path, 0o644, func(rules []*playbook.Rule) ([]*playbook.Rule, error) {
			out := rules[:0]
			for _, r := range rules {
				if !containsID(involved, r.ID) {
					out = append(out, r)
				}
			}
			return out, nil
		})
		if err != nil {
			return err
		}
		for _, r := range involved {
			lesson.RulesRemoved = append(lesson.RulesRemoved, r.ID)
		}
	}

	var newRule *playbook.Rule
	switch verdict {
	case "benign":
		if !*noAllow {
			newRule = &playbook.Rule{ID: playbook.NewID(), Verdict: playbook.Allow, Name: "allow: " + truncate(*note, 80),
				Description: "Marked benign by a human (" + lesson.Kind + ")", Handling: *note,
				Match:     playbook.Match{PathRegex: *pathRe, UARegex: *uaRe, SSHUserRegex: *sshRe},
				ExampleIP: key, CreatedBy: by, CreatedAt: now, ApprovedAt: &now}
			if *allowPrefix != "" {
				newRule.Match.IPPrefixes = strings.Split(*allowPrefix, ",")
			} else {
				newRule.Match.IPPrefixes = []string{key}
			}
		}
		// The enforcer also lifts the block once it sees the allow rule;
		// unblocking here makes it immediate (and covers -no-allow).
		if _, err := enforce.Call(cfg.EnforcerSocket, enforce.Request{Op: "unblock", IP: key, Actor: "human", Reason: "marked benign: " + *note}); err == nil {
			fmt.Println("unblocked", key)
		}
	case "malicious":
		if *pathRe != "" || *uaRe != "" || *sshRe != "" {
			newRule = &playbook.Rule{ID: playbook.NewID(), Verdict: playbook.Malicious, Name: truncate(*note, 80),
				Description: "Marked malicious by a human (" + lesson.Kind + ")", Handling: *note,
				Match: playbook.Match{PathRegex: *pathRe, UARegex: *uaRe, SSHUserRegex: *sshRe},
				Score: 40, AutoBlock: *autoBlock, TTL: config.Duration(*ttl),
				ExampleIP: key, CreatedBy: by, CreatedAt: now, ApprovedAt: &now}
		}
	}
	if newRule != nil {
		if err := newRule.Compile(); err != nil {
			return fmt.Errorf("rule: %w", err)
		}
		if err := newRule.CheckBenign(); err != nil {
			return fmt.Errorf("rule: %w", err)
		}
		err := playbook.Update(cfg.Playbook.Path, 0o644, func(rules []*playbook.Rule) ([]*playbook.Rule, error) {
			return append(rules, newRule), nil
		})
		if err != nil {
			return err
		}
		lesson.RulesCreated = append(lesson.RulesCreated, newRule.ID)
		fmt.Printf("added %s rule %s\n", newRule.Verdict, newRule.ID)
	}
	if verdict == "malicious" {
		_, err := enforce.Call(cfg.EnforcerSocket, enforce.Request{Op: "block", IP: key, TTL: *ttl, Actor: "human", Reason: "marked malicious: " + *note})
		if err != nil {
			fmt.Fprintf(os.Stderr, "block %s: %v\n", key, err)
			if len(involved) > 0 && !*removeRules {
				fmt.Fprintln(os.Stderr, "  an allow rule covers this IP; rerun with -remove-rules to drop it")
			}
		} else {
			fmt.Println("blocked", key, "for", *ttl)
		}
	}
	if len(involved) > 0 && !*removeRules {
		fmt.Println("rules involved (kept; use -remove-rules to drop them):")
		for _, r := range involved {
			fmt.Printf("  %s  %s\n", r.ID, r.Name)
		}
	}

	if err := playbook.UpdateList(cfg.Playbook.LessonsPath, 0o644, func(l []playbook.Lesson) ([]playbook.Lesson, error) {
		l = append(l, lesson)
		if len(l) > playbook.MaxLessons {
			l = l[len(l)-playbook.MaxLessons:]
		}
		return l, nil
	}); err != nil {
		return err
	}
	if review != nil {
		if err := playbook.UpdateList(cfg.ReviewsPath(), 0o660, func(l []playbook.Review) ([]playbook.Review, error) {
			out := l[:0]
			for _, r := range l {
				if r.ID != review.ID {
					out = append(out, r)
				}
			}
			return out, nil
		}); err != nil {
			return err
		}
	}
	a, err := audit.Open(filepath.Join(cfg.StateDir, "playbook-audit.jsonl"))
	if err != nil {
		return err
	}
	fmt.Println("lesson recorded", lesson.ID)
	return a.Write(by, "lesson", lesson, "ok")
}

func containsRule(list []*playbook.Rule, r *playbook.Rule) bool {
	return containsID(list, r.ID)
}

func containsID(list []*playbook.Rule, id string) bool {
	for _, r := range list {
		if r.ID == id {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// printLessons is used by "playbook list".
func printLessons(cfg *config.Config) {
	lessons, err := playbook.LoadList[playbook.Lesson](cfg.Playbook.LessonsPath)
	if err != nil || len(lessons) == 0 {
		return
	}
	fmt.Println("\nLESSONS (latest 20)")
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	for i := max(0, len(lessons)-20); i < len(lessons); i++ {
		l := lessons[i]
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", l.Time.Local().Format("2006-01-02"), l.IP, l.Verdict, l.Kind, truncate(l.Note, 70))
	}
	w.Flush()
}

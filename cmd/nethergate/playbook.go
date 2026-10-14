package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/kuramichi2010/nethergate/internal/audit"
	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/detect"
	"github.com/kuramichi2010/nethergate/internal/logscan"
	"github.com/kuramichi2010/nethergate/internal/mcp"
	"github.com/kuramichi2010/nethergate/internal/playbook"
)

const playbookUsage = `usage: nethergate playbook list
       nethergate playbook show <id>      rule detail + replay over the current logs
       nethergate playbook approve <id>   activate a proposed rule (needs write access to the approved file)
       nethergate playbook reject <id>    discard a proposal
       nethergate playbook remove <id>    deactivate an approved rule`

func runPlaybook(cfg *config.Config, args []string) error {
	if len(args) == 0 || (args[0] != "list" && len(args) != 2) {
		return errors.New(playbookUsage)
	}
	approved, errs := playbook.Load(cfg.Playbook.Path)
	for _, err := range errs {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}
	pending, errs := playbook.Load(cfg.ProposalsPath())
	for _, err := range errs {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}
	find := func(rules []*playbook.Rule, id string) *playbook.Rule {
		for _, r := range rules {
			if r.ID == id {
				return r
			}
		}
		return nil
	}
	logAction := func(action string, r *playbook.Rule) error {
		a, err := audit.Open(filepath.Join(cfg.StateDir, "playbook-audit.jsonl"))
		if err != nil {
			return err
		}
		return a.Write("human:"+currentUser(), action, r, "ok")
	}

	switch args[0] {
	case "list":
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "STATUS\tID\tVERDICT\tNAME\tSCORE\tAUTO_BLOCK\tMATCH")
		for _, set := range []struct {
			status string
			rules  []*playbook.Rule
		}{{"approved", approved}, {"PENDING", pending}} {
			for _, r := range set.rules {
				m, _ := json.Marshal(r.Match)
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%v\t%s\n", set.status, r.ID, r.Verdict, r.Name, r.Score, r.AutoBlock, m)
			}
		}
		err := w.Flush()
		printLessons(cfg)
		return err
	case "show":
		r := find(approved, args[1])
		others := approved
		if r == nil {
			if r = find(pending, args[1]); r == nil {
				return fmt.Errorf("no rule %s", args[1])
			}
		} else {
			others = nil // replay the approved rule on its own
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		scan := func(rules []*playbook.Rule) (*detect.Analyzer, error) { return logscan.Scan(cfg, rules, time.Now()) }
		rep, _, err := mcp.ReplayRule(scan, others, r, cfg.Window.D())
		if err != nil {
			return fmt.Errorf("replay: %w", err)
		}
		fmt.Printf("\nReplay over the last %s of logs:\n", cfg.Window.D())
		_ = enc.Encode(rep)
		return nil
	case "approve":
		r := find(pending, args[1])
		if r == nil {
			return fmt.Errorf("no pending proposal %s", args[1])
		}
		now := time.Now().UTC()
		r.ApprovedAt = &now
		err := playbook.Update(cfg.Playbook.Path, 0o644, func(rules []*playbook.Rule) ([]*playbook.Rule, error) {
			if find(rules, r.ID) != nil {
				return nil, fmt.Errorf("%s is already approved", r.ID)
			}
			return append(rules, r), nil
		})
		if err != nil {
			return err
		}
		if err := removeFrom(cfg.ProposalsPath(), 0o660, r.ID); err != nil {
			return fmt.Errorf("approved, but could not remove the proposal: %w", err)
		}
		fmt.Printf("approved %s (%s). nethergate watch picks it up within seconds.\n", r.ID, r.Name)
		return logAction("playbook_approve", r)
	case "reject":
		r := find(pending, args[1])
		if r == nil {
			return fmt.Errorf("no pending proposal %s", args[1])
		}
		if err := removeFrom(cfg.ProposalsPath(), 0o660, r.ID); err != nil {
			return err
		}
		fmt.Println("rejected", r.ID)
		return logAction("playbook_reject", r)
	case "remove":
		r := find(approved, args[1])
		if r == nil {
			return fmt.Errorf("no approved rule %s", args[1])
		}
		if err := removeFrom(cfg.Playbook.Path, 0o644, r.ID); err != nil {
			return err
		}
		fmt.Println("removed", r.ID)
		return logAction("playbook_remove", r)
	}
	return errors.New(playbookUsage)
}

func removeFrom(path string, mode os.FileMode, id string) error {
	return playbook.Update(path, mode, func(rules []*playbook.Rule) ([]*playbook.Rule, error) {
		out := rules[:0]
		for _, r := range rules {
			if r.ID != id {
				out = append(out, r)
			}
		}
		return out, nil
	})
}

func currentUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return fmt.Sprint(os.Getuid())
}

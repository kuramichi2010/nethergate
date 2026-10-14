package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/enforce"
)

const aiUsage = `usage: nethergate ai status
       nethergate ai pause  -reason "..."   stop every AI action now (blocks, unblocks, proposals, reviews, reports)
       nethergate ai resume -reason "..."   allow AI actions again (after checking why it was paused)`

// runAI is the human kill switch. The state lives in the enforcer, so a
// hijacked AI can neither see the switch as a tool nor flip it back.
func runAI(cfg *config.Config, args []string) error {
	if len(args) == 0 {
		return errors.New(aiUsage)
	}
	fs := flag.NewFlagSet("ai", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
		return errors.New(aiUsage)
	}
	op := map[string]string{"status": "ai_status", "pause": "ai_pause", "resume": "ai_resume"}[args[0]]
	if op == "" {
		return errors.New(aiUsage)
	}
	if op != "ai_status" && *reason == "" {
		return errors.New("-reason is required: it goes into the audit log")
	}
	resp, err := enforce.Call(cfg.EnforcerSocket, enforce.Request{Op: op, Reason: *reason + " (by " + currentUser() + ")"})
	if err != nil {
		return err
	}
	st := resp.AI
	if st == nil {
		return errors.New("enforcer returned no AI state")
	}
	fmt.Printf("mode:   %s\n", st.Mode)
	if st.Paused {
		fmt.Printf("status: PAUSED since %s by %s\nreason: %s\n", st.Since.Local().Format(time.DateTime), st.By, st.Reason)
	} else {
		fmt.Println("status: active")
	}
	return nil
}

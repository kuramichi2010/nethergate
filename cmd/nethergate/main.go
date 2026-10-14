// Command nethergate lets an AI agent defend a server through a narrow,
// audited gate.
//
//	nethergate enforcer   privileged: owns the nftables blocklist
//	nethergate watch      unprivileged: tails logs, auto-blocks, triggers AI triage
//	nethergate mcp        unprivileged: MCP server on stdio for Claude Code / Codex
//	nethergate scan       print current incidents as JSON
//	nethergate verify     verify the audit log hash chain
//	nethergate nft-setup  print the nftables ruleset to install
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/michitaka/nethergate/internal/audit"
	"github.com/michitaka/nethergate/internal/config"
	"github.com/michitaka/nethergate/internal/detect"
	"github.com/michitaka/nethergate/internal/enforce"
	"github.com/michitaka/nethergate/internal/mcp"
	"github.com/michitaka/nethergate/internal/osint"
	"github.com/michitaka/nethergate/internal/playbook"
	"github.com/michitaka/nethergate/internal/policy"
	"github.com/michitaka/nethergate/internal/watch"
)

const nftRuleset = `table inet nethergate {
	set block4 { type ipv4_addr; flags timeout; size 65536; }
	set block6 { type ipv6_addr; flags timeout; size 65536; }
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @block4 counter drop
		ip6 saddr @block6 counter drop
	}
	# Traffic to containers / VMs (e.g. Docker-published ports) is DNATed
	# and never reaches the input hook, so drop it on forward as well.
	chain forward {
		type filter hook forward priority -10; policy accept;
		ip saddr @block4 counter drop
		ip6 saddr @block6 counter drop
	}
}
`

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nethergate [-config path] enforcer|watch|mcp|scan|verify|nft-setup|playbook ...|review ...|correct ...")
	os.Exit(2)
}

func main() {
	cfgPath := flag.String("config", "/etc/nethergate/config.json", "config file")
	flag.Parse()
	multi := map[string]bool{"playbook": true, "review": true, "correct": true}
	if flag.NArg() < 1 || (flag.NArg() > 1 && !multi[flag.Arg(0)]) {
		usage()
	}
	log.SetFlags(log.LstdFlags | log.LUTC)
	cmd := flag.Arg(0)
	if cmd == "nft-setup" {
		fmt.Print(nftRuleset)
		return
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	openAudit := func(dir, name string) *audit.Log {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			log.Fatal(err)
		}
		a, err := audit.Open(filepath.Join(dir, name))
		if err != nil {
			log.Fatal(err)
		}
		return a
	}

	switch cmd {
	case "enforcer":
		a := openAudit(cfg.EnforcerStateDir, "enforcer-audit.jsonl")
		srv := enforce.NewServer(policy.New(cfg.Policy, cfg.AllowPrefixes), a, cfg.EnforcerClientUIDs, cfg.Policy.DryRun)
		srv.StatePath = filepath.Join(cfg.EnforcerStateDir, "blocks.json")
		srv.PlaybookPath = cfg.Playbook.Path
		if err := srv.LoadState(); err != nil {
			log.Printf("restore blocks: %v", err)
		}
		go func() { <-ctx.Done(); os.Remove(cfg.EnforcerSocket); os.Exit(0) }()
		log.Fatal(srv.Serve(cfg.EnforcerSocket))
	case "watch":
		d := &watch.Daemon{Cfg: cfg, Audit: openAudit(cfg.StateDir, "watch-audit.jsonl")}
		if err := d.Run(ctx); err != nil {
			log.Fatal(err)
		}
	case "mcp":
		// stdout is the protocol channel: logs must go to stderr only.
		log.SetOutput(os.Stderr)
		var oc *osint.Client
		if cfg.OSINT.Enabled {
			oc = osint.New(cfg.OSINT.AbuseIPDBKeyEnv)
		}
		rules, errs := playbook.Load(cfg.Playbook.Path)
		for _, err := range errs {
			log.Printf("playbook: %v", err)
		}
		s := &mcp.Server{
			Cfg: cfg, Audit: openAudit(cfg.StateDir, "mcp-audit.jsonl"), OSINT: oc, Rules: rules,
			Scan:    func(r []*playbook.Rule) (*detect.Analyzer, error) { return watch.Scan(cfg, r, time.Now()) },
			Enforce: func(r enforce.Request) (enforce.Response, error) { return enforce.Call(cfg.EnforcerSocket, r) },
		}
		if err := s.Serve(ctx, os.Stdin, os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "scan":
		rules, errs := playbook.Load(cfg.Playbook.Path)
		for _, err := range errs {
			log.Printf("playbook: %v", err)
		}
		a, err := watch.Scan(cfg, rules, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(a.Incidents(time.Now().Add(-cfg.Window.D()), 1))
	case "playbook":
		if err := runPlaybook(cfg, flag.Args()[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "review":
		if err := runReview(cfg, flag.Args()[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "correct":
		if err := runCorrect(cfg, flag.Args()[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "verify":
		bad := false
		for _, p := range []string{
			filepath.Join(cfg.EnforcerStateDir, "enforcer-audit.jsonl"),
			filepath.Join(cfg.StateDir, "watch-audit.jsonl"),
			filepath.Join(cfg.StateDir, "mcp-audit.jsonl"),
			filepath.Join(cfg.StateDir, "playbook-audit.jsonl"),
		} {
			if _, err := os.Stat(p); os.IsNotExist(err) {
				continue
			}
			cnt, err := audit.Verify(p)
			if err != nil {
				bad = true
				fmt.Printf("%s: TAMPERED after %d valid records: %v\n", p, cnt, err)
			} else {
				fmt.Printf("%s: ok (%d records)\n", p, cnt)
			}
		}
		if bad {
			os.Exit(1)
		}
	default:
		usage()
	}
}

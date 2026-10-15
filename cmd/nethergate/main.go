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
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/kuramichi2010/nethergate/internal/audit"
	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/detect"
	"github.com/kuramichi2010/nethergate/internal/enforce"
	"github.com/kuramichi2010/nethergate/internal/logscan"
	"github.com/kuramichi2010/nethergate/internal/mcp"
	"github.com/kuramichi2010/nethergate/internal/osint"
	"github.com/kuramichi2010/nethergate/internal/playbook"
	"github.com/kuramichi2010/nethergate/internal/policy"
	"github.com/kuramichi2010/nethergate/internal/watch"
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
	fmt.Fprintln(os.Stderr, "usage: nethergate [-config path] enforcer|watch|mcp|scan|verify|nft-setup|playbook ...|review ...|correct ...|ai status|pause|resume|proxies cloudflare")
	os.Exit(2)
}

func main() {
	cfgPath := flag.String("config", "/etc/nethergate/config.json", "config file")
	flag.Parse()
	multi := map[string]bool{"playbook": true, "review": true, "correct": true, "verify": true, "ai": true, "proxies": true}
	if flag.NArg() < 1 || (flag.NArg() > 1 && !multi[flag.Arg(0)]) {
		usage()
	}
	log.SetFlags(log.LstdFlags | log.LUTC)
	cmd := flag.Arg(0)
	if cmd == "proxies" {
		if err := runProxies(flag.Args()[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
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
		// A CDN in front of us is never blocked: that would take the whole site down.
		allow := append(append([]netip.Prefix(nil), cfg.AllowPrefixes...), cfg.ProxyPrefixes...)
		srv := enforce.NewServer(policy.New(cfg.Policy, allow), a, cfg.EnforcerClients, cfg.Policy, cfg.Policy.DryRun)
		backends, err := buildBackends(cfg, srv)
		if err != nil {
			log.Fatal(err)
		}
		srv.Backends = backends
		// Automated blocks are re-authorised from the logs, not from the caller.
		srv.Verify = func(ip netip.Addr) (*detect.Incident, []*playbook.Rule, error) {
			rules, errs := playbook.Load(cfg.Playbook.Path)
			for _, err := range errs {
				log.Printf("playbook: %v", err)
			}
			an, err := logscan.ScanIP(cfg, rules, ip, time.Now())
			if err != nil {
				return nil, nil, err
			}
			return an.Get(ip), rules, nil
		}
		// The enforcer has no network access: its anchors go to the journal.
		pub := &audit.Publisher{}
		auditPath := filepath.Join(cfg.EnforcerStateDir, "enforcer-audit.jsonl")
		srv.OnAudit = func() { n, h := a.Head(); pub.Publish(auditPath, n, h) }
		go func() {
			for {
				srv.OnAudit()
				time.Sleep(cfg.AuditAnchor.Interval.D())
			}
		}()
		srv.StatePath = filepath.Join(cfg.EnforcerStateDir, "blocks.json")
		srv.AIStatePath = filepath.Join(cfg.EnforcerStateDir, "ai-state.json")
		srv.PlaybookPath = cfg.Playbook.Path
		if err := srv.LoadState(); err != nil {
			log.Printf("restore blocks: %v", err)
		}
		go func() { <-ctx.Done(); os.Remove(cfg.EnforcerSocket); os.Exit(0) }()
		log.Fatal(srv.Serve(cfg.EnforcerSocket))
	case "watch":
		mustRunAs(cfg, "watch", cfg.EnforcerClients.WatchUIDs)
		d := &watch.Daemon{Cfg: cfg, Audit: openAudit(cfg.StateDir, "watch-audit.jsonl")}
		if err := d.Run(ctx); err != nil {
			log.Fatal(err)
		}
	case "mcp":
		// stdout is the protocol channel: logs must go to stderr only.
		log.SetOutput(os.Stderr)
		mustRunAs(cfg, "mcp", cfg.EnforcerClients.MCPUIDs)
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
			Scan:    func(r []*playbook.Rule) (*detect.Analyzer, error) { return logscan.Scan(cfg, r, time.Now()) },
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
		a, err := logscan.Scan(cfg, rules, time.Now())
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
	case "ai":
		if err := runAI(cfg, flag.Args()[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "correct":
		if err := runCorrect(cfg, flag.Args()[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "verify":
		if err := runVerify(cfg, flag.Args()[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		usage()
	}
}

// runVerify checks every audit chain and, with -anchors, that the logs
// still contain the heads published earlier (journal / SIEM export).
func runVerify(cfg *config.Config, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	anchorFile := fs.String("anchors", "", "file with NETHERGATE-ANCHOR lines (e.g. journalctl -u 'nethergate-*' output)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var anchors map[string][]audit.Anchor
	if *anchorFile != "" {
		f, err := os.Open(*anchorFile)
		if err != nil {
			return err
		}
		anchors, err = audit.ParseAnchors(f)
		f.Close()
		if err != nil {
			return err
		}
	}
	bad := false
	for _, p := range []string{
		filepath.Join(cfg.EnforcerStateDir, "enforcer-audit.jsonl"),
		filepath.Join(cfg.StateDir, "watch-audit.jsonl"),
		filepath.Join(cfg.StateDir, "mcp-audit.jsonl"),
		filepath.Join(cfg.StateDir, "playbook-audit.jsonl"),
	} {
		want := anchors[filepath.Base(p)]
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if len(want) > 0 {
				bad = true
				fmt.Printf("%s: MISSING but %d anchors were published for it (deleted)\n", p, len(want))
			}
			continue
		}
		cnt, err := audit.VerifyAnchors(p, want)
		switch {
		case err != nil:
			bad = true
			fmt.Printf("%s: TAMPERED after %d valid records: %v\n", p, cnt, err)
		case len(want) > 0:
			fmt.Printf("%s: ok (%d records, %d anchors match)\n", p, cnt, len(want))
		default:
			fmt.Printf("%s: ok (%d records, no anchors checked)\n", p, cnt)
		}
	}
	if bad {
		return errors.New("audit verification failed")
	}
	return nil
}

// mustRunAs stops a daemon that would reach the enforcer with the wrong
// role: e.g. an MCP server (the AI) running as root would be treated as a
// human, and one running as the watch user as the rule engine.
func mustRunAs(cfg *config.Config, role string, uids []int) {
	uid := os.Getuid()
	if slices.Contains(uids, uid) {
		return
	}
	c := cfg.EnforcerClients
	if uid == 0 || slices.Contains(c.AdminUIDs, uid) || slices.Contains(c.WatchUIDs, uid) || slices.Contains(c.MCPUIDs, uid) {
		log.Fatalf("refusing to run %s as uid %d: that uid has another role at the enforcer; run it as one of enforcer_clients.%s_uids %v", role, uid, role, uids)
	}
	log.Printf("warning: uid %d is not in enforcer_clients.%s_uids; the enforcer will refuse its requests", uid, role)
}

// buildBackends creates the configured enforcement backends. API tokens are
// read here, in the enforcer only; the AI and the watch daemon never see them.
func buildBackends(cfg *config.Config, srv *enforce.Server) ([]enforce.Backend, error) {
	var out []enforce.Backend
	for _, name := range cfg.Enforcement.Backends {
		switch name {
		case "nftables":
			out = append(out, srv.NFTBackend())
		case "cloudflare":
			cf := cfg.Enforcement.Cloudflare
			tok := os.Getenv(cf.TokenEnv)
			if tok == "" {
				return nil, fmt.Errorf("enforcement.cloudflare: environment variable %s is empty (put it in /etc/nethergate/enforcer.env)", cf.TokenEnv)
			}
			out = append(out, &enforce.CloudflareBackend{ZoneID: cf.ZoneID, Token: tok, Base: cf.APIBase})
		}
	}
	log.Printf("enforcement backends: %v", cfg.Enforcement.Backends)
	return out, nil
}

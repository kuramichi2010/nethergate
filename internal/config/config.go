// Package config loads and validates the nethergate configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Duration is a time.Duration that unmarshals from strings like "1h".
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d Duration) D() time.Duration { return time.Duration(d) }

type LogSource struct {
	Path   string `json:"path"`
	Format string `json:"format"` // "nginx" | "sshd"
}

type Policy struct {
	DryRun           bool     `json:"dry_run"`
	DefaultTTL       Duration `json:"default_ttl"`
	MaxTTL           Duration `json:"max_ttl"`
	MaxBlocksPerHour int      `json:"max_blocks_per_hour"`
	// Rule engine blocks automatically at or above this score (0 disables).
	AutoBlockScore int `json:"auto_block_score"`
	// The AI may only block IPs whose incident score is at least this.
	AIMinScore int `json:"ai_min_score"`
}

type OSINT struct {
	Enabled bool `json:"enabled"`
	// Name of an environment variable holding an AbuseIPDB key (optional).
	AbuseIPDBKeyEnv string `json:"abuseipdb_key_env"`
}

type Triage struct {
	// Command run when an incident needs AI judgement. The prompt is
	// passed on stdin. Empty disables AI triage.
	Command  []string `json:"command"`
	MinScore int      `json:"min_score"`
	Cooldown Duration `json:"cooldown"`
	Timeout  Duration `json:"timeout"`
}

type Playbook struct {
	// Approved rules, loaded at startup. Must be writable by root only:
	// the agent reads it, a human approves rules into it.
	Path string `json:"path"`
	// Human judgements (answers to AI reviews, corrections). Root-only, like Path.
	LessonsPath string `json:"lessons_path"`
	// A proposed rule is rejected if, replayed over the current window,
	// it matches more distinct source IPs than this (likely too broad).
	MaxMatchIPs int `json:"max_match_ips"`
}

type Notify struct {
	// Slack/Discord-compatible incoming webhook URL (optional).
	WebhookURL string `json:"webhook_url"`
}

type Config struct {
	Logs     []LogSource `json:"logs"`
	StateDir string      `json:"state_dir"`
	// Owned by the enforcer user alone, so the unprivileged agent cannot
	// rewrite or delete the enforcer's audit log or block state.
	EnforcerStateDir string `json:"enforcer_state_dir"`
	ReportDir        string `json:"report_dir"`
	EnforcerSocket   string `json:"enforcer_socket"`
	// UIDs allowed to talk to the enforcer socket.
	EnforcerClientUIDs []int    `json:"enforcer_client_uids"`
	Allowlist          []string `json:"allowlist"`
	Window             Duration `json:"window"`
	MaxScanBytes       int64    `json:"max_scan_bytes"`
	Policy             Policy   `json:"policy"`
	OSINT              OSINT    `json:"osint"`
	Triage             Triage   `json:"triage"`
	Notify             Notify   `json:"notify"`
	Playbook           Playbook `json:"playbook"`

	AllowPrefixes []netip.Prefix `json:"-"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Default()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, c.Validate()
}

func Default() *Config {
	return &Config{
		StateDir:         "/var/lib/nethergate",
		EnforcerStateDir: "/var/lib/nethergate-enforcer",
		ReportDir:        "/var/lib/nethergate/reports",
		EnforcerSocket:   "/run/nethergate/enforcer.sock",
		Window:           Duration(24 * time.Hour),
		MaxScanBytes:     64 << 20,
		Policy: Policy{
			DryRun:           true,
			DefaultTTL:       Duration(time.Hour),
			MaxTTL:           Duration(24 * time.Hour),
			MaxBlocksPerHour: 60,
			AutoBlockScore:   90,
			AIMinScore:       30,
		},
		OSINT:    OSINT{Enabled: true},
		Playbook: Playbook{Path: "/etc/nethergate/playbook.json", LessonsPath: "/etc/nethergate/lessons.json", MaxMatchIPs: 200},
		Triage:   Triage{MinScore: 60, Cooldown: Duration(15 * time.Minute), Timeout: Duration(5 * time.Minute)},
	}
}

func (c *Config) Validate() error {
	var errs []error
	c.AllowPrefixes = nil
	for _, s := range c.Allowlist {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err2 := netip.ParseAddr(s)
			if err2 != nil || a.Zone() != "" {
				errs = append(errs, fmt.Errorf("allowlist entry %q: %w", s, err))
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		// The policy unmaps ::ffff:a.b.c.d to IPv4, so the allowlist must too.
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		c.AllowPrefixes = append(c.AllowPrefixes, p.Masked())
	}
	for _, l := range c.Logs {
		if l.Format != "nginx" && l.Format != "sshd" {
			errs = append(errs, fmt.Errorf("log %s: unknown format %q", l.Path, l.Format))
		}
	}
	if len(c.EnforcerSocket) >= 108 {
		errs = append(errs, errors.New("enforcer_socket path must be shorter than 108 bytes (unix socket limit)"))
	}
	if c.Policy.MaxTTL <= 0 || c.Policy.DefaultTTL <= 0 || c.Policy.DefaultTTL > c.Policy.MaxTTL {
		errs = append(errs, errors.New("policy: need 0 < default_ttl <= max_ttl"))
	}
	if c.Policy.MaxBlocksPerHour <= 0 {
		errs = append(errs, errors.New("policy: max_blocks_per_hour must be > 0"))
	}
	if c.Window <= 0 {
		errs = append(errs, errors.New("window must be > 0"))
	}
	if c.MaxScanBytes <= 0 {
		errs = append(errs, errors.New("max_scan_bytes must be > 0"))
	}
	if c.StateDir == "" || c.EnforcerStateDir == "" || c.ReportDir == "" {
		errs = append(errs, errors.New("state_dir, enforcer_state_dir and report_dir must be set"))
	} else if c.StateDir == c.EnforcerStateDir {
		errs = append(errs, errors.New("enforcer_state_dir must differ from state_dir (the agent must not own the enforcer's audit log)"))
	}
	if len(c.Triage.Command) > 0 && (c.Triage.Timeout <= 0 || c.Triage.Cooldown < 0) {
		errs = append(errs, errors.New("triage: need timeout > 0 and cooldown >= 0"))
	}
	if c.Notify.WebhookURL != "" {
		if u, err := url.Parse(c.Notify.WebhookURL); err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, errors.New("notify.webhook_url must be an https:// URL"))
		}
	}
	if c.Playbook.Path == "" || c.Playbook.LessonsPath == "" || c.Playbook.MaxMatchIPs <= 0 {
		errs = append(errs, errors.New("playbook: path, lessons_path and max_match_ips > 0 are required"))
	}
	if c.Policy.AIMinScore < 1 {
		errs = append(errs, errors.New("policy: ai_min_score must be >= 1 (the AI must not block IPs that never touched us)"))
	}
	return errors.Join(errs...)
}

// ReviewsPath is where the AI queues cases it could not decide.
func (c *Config) ReviewsPath() string { return filepath.Join(c.StateDir, "reviews.json") }

// ProposalsPath is where the agent stores rules awaiting human approval.
func (c *Config) ProposalsPath() string { return filepath.Join(c.StateDir, "playbook-proposed.json") }

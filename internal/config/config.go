// Package config loads and validates the nethergate configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	Path string `json:"path"`
	// "nginx": combined format; $remote_addr must already be the client
	// (nginx real_ip module behind a CDN).
	// "nginx_proxy": combined + a final quoted "$http_x_forwarded_for";
	// the client is taken from it when the peer is a trusted proxy.
	// "sshd": OpenSSH auth log.
	Format string `json:"format"`
}

type Policy struct {
	DryRun     bool     `json:"dry_run"`
	DefaultTTL Duration `json:"default_ttl"`
	MaxTTL     Duration `json:"max_ttl"`
	// Global cap on automated blocks (rules + playbook + ai) per hour.
	MaxBlocksPerHour int `json:"max_blocks_per_hour"`
	// Per-actor caps per hour, so a misbehaving AI cannot use up the
	// budget the rule engine needs (and vice versa). Humans are not capped.
	QuotaPerHour map[string]int `json:"quota_per_hour"`
	// Rule engine blocks automatically at or above this score (0 disables).
	AutoBlockScore int `json:"auto_block_score"`
	// The AI may only block IPs whose incident score is at least this.
	AIMinScore int `json:"ai_min_score"`
	// Limits that assume the AI may be hijacked by prompt injection.
	AI AIGuard `json:"ai"`
}

// AIGuard bounds what a prompt-injected AI can do.
type AIGuard struct {
	// "act" (default): the AI may place short blocks itself.
	// "advise": the AI can only recommend; its block requests become
	// reviews that a human approves. The enforcer refuses AI blocks.
	Mode string `json:"mode"`
	// Longest block the AI may place (shorter than max_ttl).
	MaxTTL Duration `json:"max_ttl"`
	// Quarantine: after this many refused AI requests within the window,
	// the enforcer stops accepting any AI action until a human resumes it.
	QuarantineRejections int      `json:"quarantine_rejections"`
	QuarantineWindow     Duration `json:"quarantine_window"`
	// A source with this many successful requests or distinct user agents
	// looks shared (NAT, proxy, office): the AI may not block it alone.
	SharedMinOK  int `json:"shared_min_ok_requests"`
	SharedMinUAs int `json:"shared_min_user_agents"`
	// Per-tool limits across MCP sessions (calls per hour; reports per day).
	EnrichPerHour   int `json:"enrich_per_hour"`
	ReviewsPerHour  int `json:"reviews_per_hour"`
	ProposalsPerDay int `json:"proposals_per_day"`
	ReportsPerDay   int `json:"reports_per_day"`
	ReportDirMaxMB  int `json:"report_dir_max_mb"`
	// Widest allow range the AI may propose (humans are not limited).
	MaxAllowPrefixV4 int `json:"max_allow_prefix_v4"`
	MaxAllowPrefixV6 int `json:"max_allow_prefix_v6"`
}

// AIAdvisory reports whether the AI may only recommend blocks.
func (p Policy) AIAdvisory() bool { return p.AI.Mode == "advise" }

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

type EnforcerClients struct {
	WatchUIDs []int `json:"watch_uids"` // actor "rules" / "playbook"
	MCPUIDs   []int `json:"mcp_uids"`   // actor "ai"
	AdminUIDs []int `json:"admin_uids"` // actor "human" (root always is)
}

// AuditAnchor publishes the audit chain heads (record count + hash) outside
// the host, so truncating or rewriting a log is detectable later.
type AuditAnchor struct {
	Interval Duration `json:"interval"`
	// Optional HTTPS endpoint that receives {"file","n","hash","time"} JSON.
	URL string `json:"url"`
}

// Forward ships every audit record to a remote syslog server or SIEM.
type Forward struct {
	Interval Duration       `json:"interval"`
	Syslog   *ForwardSyslog `json:"syslog,omitempty"`
	HTTP     *ForwardHTTP   `json:"http,omitempty"`
}

type ForwardSyslog struct {
	Address    string `json:"address"`     // host:6514
	CAFile     string `json:"ca_file"`     // optional; system roots otherwise
	ServerName string `json:"server_name"` // optional TLS name override
	// Plaintext TCP, only for a relay on this host (e.g. 127.0.0.1:514).
	Plaintext bool `json:"plaintext"`
}

type ForwardHTTP struct {
	URL      string `json:"url"`       // https://
	Format   string `json:"format"`    // "ndjson" (default) | "splunk_hec"
	TokenEnv string `json:"token_env"` // env var holding the token (see /etc/nethergate/env)
}

// Metrics exposes Prometheus metrics from the watch daemon.
type Metrics struct {
	// e.g. "127.0.0.1:9464"; empty disables. Loopback only unless
	// allow_remote is set (put a TLS proxy or an OTel collector in front).
	Listen      string `json:"listen"`
	AllowRemote bool   `json:"allow_remote"`
}

// Enforcement selects where blocks are applied. "nftables" drops packets
// at this host (direct connections). Behind a CDN the attacker never
// connects directly, so the block must happen at the CDN: "cloudflare"
// adds an IP Access Rule through the Cloudflare API.
type Enforcement struct {
	Backends   []string           `json:"backends"` // default ["nftables"]
	Cloudflare *CloudflareBackend `json:"cloudflare,omitempty"`
}

type CloudflareBackend struct {
	ZoneID string `json:"zone_id"`
	// Environment variable with an API token limited to
	// "Zone > Firewall Services > Edit" on this zone. Only the enforcer
	// reads it; the AI and the watch daemon never see it.
	TokenEnv string `json:"token_env"`
	// API base, overridable for tests.
	APIBase string `json:"api_base,omitempty"`
}

func (e *Enforcement) validate() error {
	if len(e.Backends) == 0 {
		e.Backends = []string{"nftables"}
	}
	seen := map[string]bool{}
	for _, b := range e.Backends {
		if seen[b] {
			return fmt.Errorf("enforcement.backends: %q listed twice", b)
		}
		seen[b] = true
		switch b {
		case "nftables":
		case "cloudflare":
			cf := e.Cloudflare
			if cf == nil || cf.ZoneID == "" || cf.TokenEnv == "" {
				return errors.New("enforcement.cloudflare needs zone_id and token_env")
			}
			if cf.APIBase == "" {
				cf.APIBase = "https://api.cloudflare.com/client/v4"
			}
			if u, err := url.Parse(cf.APIBase); err != nil || u.Scheme != "https" {
				return errors.New("enforcement.cloudflare.api_base must be https")
			}
		default:
			return fmt.Errorf("enforcement.backends: unknown backend %q (nftables, cloudflare)", b)
		}
	}
	return nil
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
	// Which UIDs may talk to the enforcer, by role. The enforcer derives the
	// actor from the caller's UID; requests cannot claim to be someone else.
	EnforcerClients EnforcerClients `json:"enforcer_clients"`
	AuditAnchor     AuditAnchor     `json:"audit_anchor"`
	Allowlist       []string        `json:"allowlist"`
	Window          Duration        `json:"window"`
	MaxScanBytes    int64           `json:"max_scan_bytes"`
	Policy          Policy          `json:"policy"`
	OSINT           OSINT           `json:"osint"`
	Triage          Triage          `json:"triage"`
	Notify          Notify          `json:"notify"`
	Playbook        Playbook        `json:"playbook"`
	Forward         Forward         `json:"forward"`
	Metrics         Metrics         `json:"metrics"`

	// CDNs / load balancers in front of this server: their addresses are
	// never blocked, and X-Forwarded-For is only believed when they send it.
	// Entries are CIDRs, addresses or presets ("cloudflare").
	TrustedProxies []string `json:"trusted_proxies"`
	// Where blocks are applied (see Enforcement).
	Enforcement Enforcement `json:"enforcement"`

	AllowPrefixes []netip.Prefix `json:"-"`
	ProxyPrefixes []netip.Prefix `json:"-"`
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
		AuditAnchor:      AuditAnchor{Interval: Duration(5 * time.Minute)},
		Forward:          Forward{Interval: Duration(5 * time.Second)},
		MaxScanBytes:     64 << 20,
		Policy: Policy{
			DryRun:           true,
			DefaultTTL:       Duration(time.Hour),
			MaxTTL:           Duration(24 * time.Hour),
			MaxBlocksPerHour: 60,
			QuotaPerHour:     map[string]int{"ai": 20, "rules": 60, "playbook": 60},
			AI: AIGuard{
				Mode: "act", MaxTTL: Duration(6 * time.Hour),
				QuarantineRejections: 5, QuarantineWindow: Duration(10 * time.Minute),
				SharedMinOK: 50, SharedMinUAs: 10,
				EnrichPerHour: 120, ReviewsPerHour: 30, ProposalsPerDay: 20, ReportsPerDay: 50, ReportDirMaxMB: 100,
				MaxAllowPrefixV4: 24, MaxAllowPrefixV6: 48,
			},
			AutoBlockScore: 90,
			AIMinScore:     30,
		},
		OSINT:    OSINT{Enabled: true},
		Playbook: Playbook{Path: "/etc/nethergate/playbook.json", LessonsPath: "/etc/nethergate/lessons.json", MaxMatchIPs: 200},
		Triage:   Triage{MinScore: 60, Cooldown: Duration(15 * time.Minute), Timeout: Duration(5 * time.Minute)},
	}
}

func (c *Config) Validate() error {
	var errs []error
	c.AllowPrefixes = nil
	if px, err := parseProxies(c.TrustedProxies); err != nil {
		errs = append(errs, err)
	} else {
		c.ProxyPrefixes = px
	}
	for _, l := range c.Logs {
		if l.Format == "nginx_proxy" && len(c.TrustedProxies) == 0 {
			errs = append(errs, fmt.Errorf("log %s: format nginx_proxy needs trusted_proxies (otherwise X-Forwarded-For could be forged)", l.Path))
		}
	}
	if err := c.Enforcement.validate(); err != nil {
		errs = append(errs, err)
	}
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
		if l.Format != "nginx" && l.Format != "nginx_proxy" && l.Format != "sshd" {
			errs = append(errs, fmt.Errorf("log %s: unknown format %q", l.Path, l.Format))
		}
	}
	if len(c.EnforcerSocket) >= 108 {
		errs = append(errs, errors.New("enforcer_socket path must be shorter than 108 bytes (unix socket limit)"))
	}
	if c.Policy.MaxTTL <= 0 || c.Policy.DefaultTTL <= 0 || c.Policy.DefaultTTL > c.Policy.MaxTTL {
		errs = append(errs, errors.New("policy: need 0 < default_ttl <= max_ttl"))
	}
	{
		g := c.Policy.AI
		if g.Mode != "act" && g.Mode != "advise" {
			errs = append(errs, errors.New(`policy.ai.mode must be "act" or "advise"`))
		}
		if g.MaxTTL <= 0 || g.MaxTTL > c.Policy.MaxTTL {
			errs = append(errs, errors.New("policy.ai.max_ttl must be > 0 and <= policy.max_ttl"))
		}
		if g.QuarantineRejections <= 0 || g.QuarantineWindow <= 0 {
			errs = append(errs, errors.New("policy.ai.quarantine_rejections and quarantine_window must be > 0"))
		}
		for name, v := range map[string]int{"shared_min_ok_requests": g.SharedMinOK, "shared_min_user_agents": g.SharedMinUAs,
			"enrich_per_hour": g.EnrichPerHour, "reviews_per_hour": g.ReviewsPerHour, "proposals_per_day": g.ProposalsPerDay,
			"reports_per_day": g.ReportsPerDay, "report_dir_max_mb": g.ReportDirMaxMB} {
			if v <= 0 {
				errs = append(errs, fmt.Errorf("policy.ai.%s must be > 0", name))
			}
		}
		if g.MaxAllowPrefixV4 < 8 || g.MaxAllowPrefixV4 > 32 || g.MaxAllowPrefixV6 < 16 || g.MaxAllowPrefixV6 > 128 {
			errs = append(errs, errors.New("policy.ai.max_allow_prefix_v4 must be 8..32 and max_allow_prefix_v6 16..128"))
		}
	}
	if c.Policy.MaxBlocksPerHour <= 0 {
		errs = append(errs, errors.New("policy: max_blocks_per_hour must be > 0"))
	}
	for _, a := range []string{"ai", "rules", "playbook"} {
		if c.Policy.QuotaPerHour[a] <= 0 {
			errs = append(errs, fmt.Errorf("policy: quota_per_hour.%s must be > 0", a))
		}
	}
	for a := range c.Policy.QuotaPerHour {
		if a != "ai" && a != "rules" && a != "playbook" {
			errs = append(errs, fmt.Errorf("policy: quota_per_hour: unknown actor %q", a))
		}
	}
	roles := map[int]string{}
	for role, uids := range map[string][]int{"watch": c.EnforcerClients.WatchUIDs, "mcp": c.EnforcerClients.MCPUIDs, "admin": c.EnforcerClients.AdminUIDs} {
		for _, u := range uids {
			if prev, ok := roles[u]; ok && prev != role {
				errs = append(errs, fmt.Errorf("enforcer_clients: uid %d has two roles (%s, %s); give each process its own user", u, prev, role))
			}
			if u == 0 && role != "admin" {
				errs = append(errs, errors.New("enforcer_clients: uid 0 is always admin"))
			}
			roles[u] = role
		}
	}
	if c.Forward.Interval <= 0 {
		errs = append(errs, errors.New("forward.interval must be > 0"))
	}
	if f := c.Forward.Syslog; f != nil {
		host, _, err := net.SplitHostPort(f.Address)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("forward.syslog.address: %w", err))
		case f.Plaintext:
			if ip, err := netip.ParseAddr(host); (err != nil || !ip.IsLoopback()) && host != "localhost" {
				errs = append(errs, errors.New("forward.syslog.plaintext is only allowed to a loopback relay; use TLS to reach another host"))
			}
		}
	}
	if f := c.Forward.HTTP; f != nil {
		if u, err := url.Parse(f.URL); err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, errors.New("forward.http.url must be an https:// URL"))
		}
		if f.Format != "" && f.Format != "ndjson" && f.Format != "splunk_hec" {
			errs = append(errs, errors.New("forward.http.format must be ndjson or splunk_hec"))
		}
	}
	if m := c.Metrics.Listen; m != "" {
		host, _, err := net.SplitHostPort(m)
		ip, perr := netip.ParseAddr(host)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("metrics.listen: %w", err))
		case !c.Metrics.AllowRemote && host != "localhost" && (perr != nil || !ip.IsLoopback()):
			errs = append(errs, errors.New("metrics.listen must be a loopback address unless metrics.allow_remote is set"))
		}
	}
	if c.AuditAnchor.Interval <= 0 {
		errs = append(errs, errors.New("audit_anchor.interval must be > 0"))
	}
	if c.AuditAnchor.URL != "" {
		if u, err := url.Parse(c.AuditAnchor.URL); err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, errors.New("audit_anchor.url must be an https:// URL"))
		}
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

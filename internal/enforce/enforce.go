// Package enforce is the only privileged component. It runs as a separate
// process with CAP_NET_ADMIN, listens on a Unix socket, and adds/removes
// single addresses in an nftables set with a timeout. It never runs a shell
// and accepts no free-form commands.
//
// It trusts none of its callers:
//   - the actor is derived from the caller's UID (watch → rules/playbook,
//     mcp → ai, admin/root → human), never from the request;
//   - automated blocks are re-authorised from the logs by the enforcer
//     itself (the incident score, or the playbook rule that triggered);
//   - the AI can only lift blocks the AI placed;
//   - every firewall change is written to the audit log first, and is
//     refused if the audit log cannot be written (fail closed).
package enforce

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kuramichi2010/nethergate/internal/audit"
	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/detect"
	"github.com/kuramichi2010/nethergate/internal/metrics"
	"github.com/kuramichi2010/nethergate/internal/playbook"
	"github.com/kuramichi2010/nethergate/internal/policy"
	"github.com/kuramichi2010/nethergate/internal/sanitize"
)

const (
	Table = "nethergate"
	Set4  = "block4"
	Set6  = "block6"
)

type Request struct {
	Op     string        `json:"op"` // "block" | "unblock" | "list"
	IP     string        `json:"ip,omitempty"`
	TTL    time.Duration `json:"ttl,omitempty"`
	Reason string        `json:"reason,omitempty"`
	// Watch only: the approved playbook rule that triggered this block.
	RuleID string `json:"rule_id,omitempty"`
}

type Role int

const (
	RoleNone Role = iota
	RoleWatch
	RoleMCP
	RoleAdmin
)

// Verifier re-derives the incident for ip from the logs, together with the
// approved playbook rules used. A nil incident means no activity.
type Verifier func(ip netip.Addr) (*detect.Incident, []*playbook.Rule, error)

// owner precedence: a block keeps its strongest owner when extended, so
// the AI cannot take over (and then lift) a block placed by rules or people.
var rank = map[string]int{"ai": 1, "rules": 2, "playbook": 3, "human": 4}

type Block struct {
	IP      string    `json:"ip"`
	Expires time.Time `json:"expires"`
	Reason  string    `json:"reason"`
	Actor   string    `json:"actor"`
}

type Response struct {
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	DryRun bool    `json:"dry_run,omitempty"`
	Blocks []Block `json:"blocks,omitempty"`
	// "metrics": Prometheus text, re-exported by the watch daemon (the
	// enforcer itself has no network access).
	Metrics string `json:"metrics,omitempty"`
	// "ai_status" / "ai_pause" / "ai_resume".
	AI *AIState `json:"ai,omitempty"`
}

type Server struct {
	Policy  *policy.Engine
	Audit   *audit.Log
	Clients config.EnforcerClients
	DryRun  bool
	// Thresholds used to re-authorise automated blocks.
	Thresholds config.Policy
	// Verify re-derives incidents from the logs. Required for automated
	// blocks; if nil or failing, they are refused (fail closed).
	Verify Verifier
	// OnAudit is called after records are appended (e.g. to publish the
	// chain head as an external anchor).
	OnAudit func()
	// AIStatePath persists the AI pause/quarantine flag across restarts.
	AIStatePath string
	metrics     *metrics.Registry
	ai          AIState
	aiRejects   []time.Time
	// StatePath persists active blocks so a restarted enforcer can still
	// list and unblock them (and re-installs them after a reboot).
	StatePath string
	// PlaybookPath: allow rules with ip_prefixes in the approved playbook
	// are enforced here too: never blocked, and existing blocks are lifted.
	PlaybookPath string
	pbStamp      string
	runNft       func(args ...string) error
	mu           sync.Mutex
	blocks       map[string]Block
}

func NewServer(p *policy.Engine, a *audit.Log, clients config.EnforcerClients, thresholds config.Policy, dryRun bool) *Server {
	m := metrics.New()
	m.Describe("nethergate_enforcer_requests_total", metrics.Counter, "Requests handled by the enforcer, by op, actor and result (ok|rejected|error).")
	m.Describe("nethergate_enforcer_audit_write_failures_total", metrics.Counter, "Audit writes that failed; firewall changes were refused (fail closed). Should always be 0.")
	m.Describe("nethergate_enforcer_unknown_peer_total", metrics.Counter, "Connections from UIDs without a role.")
	m.Describe("nethergate_enforcer_active_blocks", metrics.Gauge, "Blocks currently in place, by owner.")
	m.Describe("nethergate_enforcer_quota_remaining", metrics.Gauge, "Blocks each automated actor may still place this hour.")
	m.Describe("nethergate_enforcer_audit_records", metrics.Gauge, "Records in the enforcer audit chain.")
	m.Describe("nethergate_enforcer_dry_run", metrics.Gauge, "1 if the enforcer does not touch the firewall.")
	m.Describe("nethergate_enforcer_ai_paused", metrics.Gauge, "1 while AI actions are paused (quarantine or human).")
	m.Describe("nethergate_enforcer_ai_pauses_total", metrics.Counter, "Times AI actions were paused, by who paused them (quarantine|human).")
	return &Server{Policy: p, Audit: a, Clients: clients, Thresholds: thresholds, DryRun: dryRun, runNft: nft, blocks: map[string]Block{}, metrics: m}
}

// metricsText refreshes the gauges and renders all enforcer metrics.
// Caller holds s.mu.
func (s *Server) metricsText() string {
	m := s.metrics
	m.Reset("nethergate_enforcer_active_blocks")
	for _, owner := range []string{"ai", "rules", "playbook", "human"} {
		m.Set("nethergate_enforcer_active_blocks", 0, "owner", owner)
	}
	for _, b := range s.blocks {
		m.Add("nethergate_enforcer_active_blocks", 1, "owner", b.Actor)
	}
	for _, a := range []string{"ai", "rules", "playbook"} {
		m.Set("nethergate_enforcer_quota_remaining", float64(s.Policy.Remaining(a)), "actor", a)
	}
	n, _ := s.Audit.Head()
	m.Set("nethergate_enforcer_audit_records", float64(n))
	dry := 0.0
	if s.DryRun {
		dry = 1
	}
	m.Set("nethergate_enforcer_dry_run", dry)
	paused := 0.0
	if s.ai.Paused {
		paused = 1
	}
	m.Set("nethergate_enforcer_ai_paused", paused)
	return m.Text()
}

// RoleOf maps a peer UID to its role. Root is always admin.
func (s *Server) RoleOf(uid int) Role {
	switch {
	case uid == 0 || slices.Contains(s.Clients.AdminUIDs, uid):
		return RoleAdmin
	case slices.Contains(s.Clients.WatchUIDs, uid):
		return RoleWatch
	case slices.Contains(s.Clients.MCPUIDs, uid):
		return RoleMCP
	}
	return RoleNone
}

func nft(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %v: %v: %s", args, err, out)
	}
	return nil
}

func setFor(ip netip.Addr) string {
	if ip.Is4() {
		return Set4
	}
	return Set6
}

func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *syscall.Ucred
	var serr error
	err = raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return -1, err
	}
	if serr != nil {
		return -1, serr
	}
	return int(cred.Uid), nil
}

// LoadState restores blocks saved by a previous run and re-adds the ones
// that have not expired (a no-op if they are still in the kernel set).
func (s *Server) LoadState() error {
	s.loadAIState()
	if s.StatePath == "" {
		return nil
	}
	b, err := os.ReadFile(s.StatePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []Block
	if err := json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("%s: %w", s.StatePath, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, bl := range list {
		ip, err := policy.ParseAddr(bl.IP)
		if err != nil || !bl.Expires.After(now) {
			continue
		}
		if !s.DryRun {
			left := max(bl.Expires.Sub(now), time.Second)
			if err := s.runNft("add", "element", "inet", Table, setFor(ip), fmt.Sprintf("{ %s timeout %ds }", ip, int(left.Seconds()))); err != nil {
				log.Printf("restore %s: %v", ip, err)
				continue
			}
		}
		s.blocks[ip.String()] = bl
	}
	return nil
}

// saveState must be called with s.mu held.
func (s *Server) saveState() {
	if s.StatePath == "" {
		return
	}
	list := make([]Block, 0, len(s.blocks))
	for _, b := range s.blocks {
		list = append(list, b)
	}
	b, _ := json.Marshal(list)
	tmp, err := os.CreateTemp(filepath.Dir(s.StatePath), ".blocks-*")
	if err == nil {
		_, err = tmp.Write(b)
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp.Name(), s.StatePath)
		}
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}
	if err != nil {
		log.Printf("save state: %v", err)
	}
}

func (s *Server) Serve(path string) error {
	_ = os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer ln.Close()
	// Group-accessible only; the UID check below is the real gate.
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	log.Printf("enforcer listening on %s (dry_run=%v)", path, s.DryRun)
	go s.refreshLoop()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c *net.UnixConn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	uid, err := peerUID(c)
	role := RoleNone
	if err == nil {
		role = s.RoleOf(uid)
	}
	if role == RoleNone {
		s.metrics.Inc("nethergate_enforcer_unknown_peer_total")
		_ = s.Audit.Write(fmt.Sprintf("uid:%d", uid), "connect", nil, "denied: uid not allowed")
		_ = json.NewEncoder(c).Encode(Response{Error: "permission denied"})
		return
	}
	var req Request
	dec := json.NewDecoder(bufio.NewReader(&limitedReader{c, 8 << 10}))
	if err := dec.Decode(&req); err != nil {
		_ = json.NewEncoder(c).Encode(Response{Error: "bad request"})
		return
	}
	_ = json.NewEncoder(c).Encode(s.Do(role, req))
}

// Do executes one request from a caller with the given role.
func (s *Server) Do(role Role, req Request) Response {
	resp, actor := s.do(role, req)
	if actor == "ai" && !resp.OK && (req.Op == "block" || req.Op == "unblock") && !strings.HasPrefix(resp.Error, errAIPaused.Error()) {
		s.noteAIRejection(resp.Error)
	}
	if req.Op != "list" && req.Op != "metrics" && !strings.HasPrefix(req.Op, "ai_") {
		result := "ok"
		switch {
		case resp.OK:
		case strings.HasPrefix(resp.Error, "audit log unavailable"):
			result = "error"
			s.metrics.Inc("nethergate_enforcer_audit_write_failures_total")
		default:
			result = "rejected"
		}
		op := req.Op
		if op != "block" && op != "unblock" {
			op = "other"
		}
		s.metrics.Inc("nethergate_enforcer_requests_total", "op", op, "actor", actor, "result", result)
	}
	return resp
}

func (s *Server) do(role Role, req Request) (Response, string) {
	var actor string
	switch role {
	case RoleAdmin:
		actor = "human"
	case RoleMCP:
		actor = "ai"
	case RoleWatch:
		actor = "rules"
		if req.RuleID != "" {
			actor = "playbook"
		}
	default:
		return Response{Error: "permission denied"}, actor
	}
	if req.RuleID != "" && role != RoleWatch {
		return Response{Error: "rule_id is only accepted from the watch daemon"}, actor
	}
	// Both end up in the audit log and are shown back to the AI via "list".
	req.Reason = sanitize.Untrusted(req.Reason)
	req.RuleID = sanitize.Untrusted(req.RuleID)

	// Re-authorise automated blocks from the logs before taking the lock
	// (scanning can take a moment).
	var authErr error
	var ruleTTL time.Duration
	if req.Op == "block" && actor != "human" {
		ruleTTL, authErr = s.authorize(actor, req)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	s.refreshAllow()
	if req.Op == "list" {
		out := make([]Block, 0, len(s.blocks))
		for _, b := range s.blocks {
			out = append(out, b)
		}
		return Response{OK: true, DryRun: s.DryRun, Blocks: out}, actor
	}
	if req.Op == "metrics" {
		if role != RoleWatch && role != RoleAdmin {
			return Response{Error: "permission denied"}, actor
		}
		return Response{OK: true, Metrics: s.metricsText()}, actor
	}
	switch req.Op {
	case "ai_status":
		return Response{OK: true, AI: s.aiState()}, actor
	case "ai_pause", "ai_resume":
		if role != RoleAdmin {
			return Response{Error: "permission denied"}, actor
		}
		if req.Op == "ai_pause" {
			s.pauseAI("human", req.Reason)
		} else if err := s.resumeAI(req.Reason); err != nil {
			return Response{Error: err.Error()}, actor
		}
		return Response{OK: true, AI: s.aiState()}, actor
	}
	if actor == "ai" && s.ai.Paused {
		_ = s.Audit.Write(actor, req.Op, req, "rejected: AI paused")
		return Response{Error: fmt.Sprintf("%v since %s (%s): %s", errAIPaused, s.ai.Since.Format(time.RFC3339), s.ai.By, s.ai.Reason)}, actor
	}
	reject := func(err error) Response {
		_ = s.Audit.Write(actor, req.Op, req, "rejected: "+err.Error())
		return Response{Error: err.Error()}
	}
	if authErr != nil {
		return reject(authErr), actor
	}
	if req.Op == "unblock" {
		if role == RoleWatch {
			return reject(errors.New("the watch daemon cannot unblock")), actor
		}
		if ip, err := policy.ParseAddr(req.IP); err == nil {
			if b, ok := s.blocks[ip.String()]; ok && actor == "ai" && b.Actor != "ai" {
				return reject(fmt.Errorf("block on %s was placed by %s; only a human can lift it", ip, b.Actor)), actor
			}
		}
	}
	act := policy.Action{Kind: req.Op, IP: req.IP, TTL: req.TTL, Reason: req.Reason, Actor: actor}
	ip, ttl, err := s.Policy.Check(&act)
	if err != nil {
		return reject(err), actor
	}
	if ruleTTL > 0 {
		ttl = min(ttl, ruleTTL)
	}
	if actor == "ai" {
		ttl = min(ttl, s.Thresholds.AI.MaxTTL.D())
	}
	key := ip.String()
	detail := map[string]any{"ip": key, "ttl": ttl.String(), "reason": req.Reason, "rule_id": req.RuleID}

	switch req.Op {
	case "block":
		expires := time.Now().Add(ttl)
		old, exists := s.blocks[key]
		if exists && !old.Expires.Before(expires) {
			return Response{OK: true, DryRun: s.DryRun}, actor // already blocked at least this long
		}
		owner := actor
		if exists && rank[old.Actor] > rank[actor] {
			owner = old.Actor // extending keeps the stronger owner
		}
		// Fail closed: no firewall change that is not in the audit log.
		if err := s.Audit.Write(actor, "block_intent", detail, "pending"); err != nil {
			log.Printf("audit unavailable, refusing block of %s: %v", key, err)
			return Response{Error: "audit log unavailable; refusing to change the firewall"}, actor
		}
		if !s.DryRun {
			if exists {
				// "add element" does not refresh the timeout of an existing
				// element, so replace it to extend the block.
				_ = s.runNft("delete", "element", "inet", Table, setFor(ip), fmt.Sprintf("{ %s }", key))
			}
			err = s.runNft("add", "element", "inet", Table, setFor(ip), fmt.Sprintf("{ %s timeout %ds }", key, int(ttl.Seconds())))
		}
		if err == nil {
			s.blocks[key] = Block{IP: key, Expires: expires, Reason: req.Reason, Actor: owner}
			s.saveState()
		}
	case "unblock":
		if _, ok := s.blocks[key]; !ok {
			return reject(errors.New("not currently blocked by nethergate")), actor
		}
		if err := s.Audit.Write(actor, "unblock_intent", detail, "pending"); err != nil {
			log.Printf("audit unavailable, refusing unblock of %s: %v", key, err)
			return Response{Error: "audit log unavailable; refusing to change the firewall"}, actor
		}
		if !s.DryRun {
			err = s.runNft("delete", "element", "inet", Table, setFor(ip), fmt.Sprintf("{ %s }", key))
		}
		if err == nil {
			delete(s.blocks, key)
			s.saveState()
		}
	}
	result := "ok"
	if s.DryRun {
		result = "ok (dry-run, firewall untouched)"
	}
	if err != nil {
		result = "error: " + err.Error()
	}
	if werr := s.Audit.Write(actor, req.Op, detail, result); werr != nil {
		// The intent record is already in the log; make the gap visible.
		log.Printf("AUDIT WRITE FAILED after %s %s (%s): %v", req.Op, key, result, werr)
	}
	if s.OnAudit != nil {
		s.OnAudit()
	}
	if err != nil {
		return Response{Error: err.Error()}, actor
	}
	return Response{OK: true, DryRun: s.DryRun}, actor
}

var errAIPaused = errors.New("AI actions are paused")

// authorize re-derives the incident behind an automated block. It returns
// the TTL cap from the playbook rule, if one was used.
func (s *Server) authorize(actor string, req Request) (time.Duration, error) {
	ip, err := policy.ParseAddr(req.IP)
	if err != nil {
		return 0, err
	}
	if s.Verify == nil {
		return 0, errors.New("incident verification unavailable; automated blocks are refused")
	}
	inc, rules, err := s.Verify(ip)
	if err != nil {
		return 0, fmt.Errorf("cannot verify incident from logs: %w", err)
	}
	if inc == nil {
		return 0, fmt.Errorf("no activity from %s in the logs; refusing %s block", ip, actor)
	}
	t := s.Thresholds
	switch actor {
	case "ai":
		if t.AIAdvisory() {
			return 0, errors.New("policy.ai.mode is advise: the AI may only recommend blocks (request_human_review)")
		}
		if inc.Score < t.AIMinScore {
			return 0, fmt.Errorf("incident score %d for %s is below ai_min_score %d", inc.Score, ip, t.AIMinScore)
		}
		// An attacker behind a shared address (office NAT, mobile carrier,
		// proxy) could steer the AI into blocking everyone behind it.
		if ok, uas := inc.OKRequests(), inc.DistinctUAs(); ok >= t.AI.SharedMinOK || uas >= t.AI.SharedMinUAs {
			return 0, fmt.Errorf("%s looks shared (%d successful requests, %d user agents): legitimate users may sit behind it; ask a human", ip, ok, uas)
		}
	case "rules":
		if t.AutoBlockScore <= 0 || inc.Score < t.AutoBlockScore {
			return 0, fmt.Errorf("incident score %d for %s is below auto_block_score %d", inc.Score, ip, t.AutoBlockScore)
		}
		if inc.SSHSuccess > 0 {
			return 0, errors.New("successful SSH login from this source: a human must decide")
		}
	case "playbook":
		if inc.SSHSuccess > 0 {
			return 0, errors.New("successful SSH login from this source: a human must decide")
		}
		for _, r := range rules {
			if r.ID != req.RuleID {
				continue
			}
			if r.IsAllow() || !r.AutoBlock {
				return 0, fmt.Errorf("playbook rule %s does not authorise automatic blocks", r.ID)
			}
			if _, triggered := inc.Hits(r); !triggered {
				return 0, fmt.Errorf("playbook rule %s has not triggered for %s", r.ID, ip)
			}
			return r.EffectiveTTL(t.DefaultTTL.D()), nil
		}
		return 0, fmt.Errorf("no approved playbook rule %s", req.RuleID)
	}
	return 0, nil
}

// refreshAllow reloads playbook allow prefixes when the file changed and
// lifts blocks that are now allowlisted (a human said "this is fine").
// Caller holds s.mu.
func (s *Server) refreshAllow() {
	if s.PlaybookPath == "" {
		return
	}
	st, err := os.Stat(s.PlaybookPath)
	stamp := "missing"
	if err == nil {
		stamp = fmt.Sprintf("%d/%d", st.Size(), st.ModTime().UnixNano())
	}
	if stamp == s.pbStamp {
		return
	}
	s.pbStamp = stamp
	rules, errs := playbook.Load(s.PlaybookPath)
	for _, err := range errs {
		log.Printf("playbook: %v", err)
	}
	var prefixes []netip.Prefix
	for _, r := range rules {
		if r.IsAllow() {
			prefixes = append(prefixes, r.Prefixes()...)
		}
	}
	s.Policy.SetExtraAllow(prefixes)
	changed := false
	for key, b := range s.blocks {
		ip, err := netip.ParseAddr(key)
		if err != nil {
			continue
		}
		p, ok := s.Policy.Allowed(ip)
		if !ok {
			continue
		}
		if werr := s.Audit.Write("playbook", "unblock_intent", map[string]any{"ip": key, "reason": "now allowlisted by " + p.String()}, "pending"); werr != nil {
			log.Printf("audit unavailable, keeping block on %s: %v", key, werr)
			continue
		}
		if !s.DryRun {
			err = s.runNft("delete", "element", "inet", Table, setFor(ip), fmt.Sprintf("{ %s }", key))
		}
		result := "ok"
		if err != nil {
			result = "error: " + err.Error()
		} else {
			delete(s.blocks, key)
			changed = true
		}
		_ = s.Audit.Write("playbook", "unblock", map[string]any{"ip": key, "reason": "now allowlisted by " + p.String(), "was": b.Reason}, result)
	}
	if changed {
		s.saveState()
	}
}

// Refresh re-reads the playbook periodically even without requests.
func (s *Server) refreshLoop() {
	for range time.Tick(10 * time.Second) {
		s.mu.Lock()
		s.refreshAllow()
		s.mu.Unlock()
	}
}

func (s *Server) expire() {
	now := time.Now()
	for k, b := range s.blocks {
		if now.After(b.Expires) {
			delete(s.blocks, k)
		}
	}
}

type limitedReader struct {
	c *net.UnixConn
	n int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("request too large")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.c.Read(p)
	l.n -= n
	return n, err
}

// Call sends one request to the enforcer socket.
func Call(path string, req Request) (Response, error) {
	c, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return Response{}, fmt.Errorf("enforcer unavailable: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return Response{}, err
	}
	if !resp.OK && resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

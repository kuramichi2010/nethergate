// Package enforce is the only privileged component. It runs as a separate
// process with CAP_NET_ADMIN, listens on a Unix socket, checks the peer's
// UID, validates every request against the policy, and then adds/removes
// single addresses in an nftables set with a timeout. It never runs a shell
// and accepts no free-form commands.
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
	"sync"
	"syscall"
	"time"

	"github.com/kuramichi2010/nethergate/internal/audit"
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
	Actor  string        `json:"actor,omitempty"`
}

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
}

type Server struct {
	Policy    *policy.Engine
	Audit     *audit.Log
	AllowUIDs []int
	DryRun    bool
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

func NewServer(p *policy.Engine, a *audit.Log, uids []int, dryRun bool) *Server {
	return &Server{Policy: p, Audit: a, AllowUIDs: uids, DryRun: dryRun, runNft: nft, blocks: map[string]Block{}}
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

var actors = []string{"rules", "playbook", "ai", "human"}

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
	if err != nil || (uid != 0 && !slices.Contains(s.AllowUIDs, uid)) {
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
	_ = json.NewEncoder(c).Encode(s.Do(req))
}

// Do executes one validated request. Exported for tests and in-process use.
func (s *Server) Do(req Request) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	s.refreshAllow()
	if req.Op == "list" {
		out := make([]Block, 0, len(s.blocks))
		for _, b := range s.blocks {
			out = append(out, b)
		}
		return Response{OK: true, DryRun: s.DryRun, Blocks: out}
	}
	// Both end up in the audit log and are shown back to the AI via "list".
	req.Reason = sanitize.Untrusted(req.Reason)
	if !slices.Contains(actors, req.Actor) {
		req.Actor = sanitize.Untrusted(req.Actor)
		_ = s.Audit.Write(req.Actor, req.Op, req, "rejected: unknown actor")
		return Response{Error: fmt.Sprintf("unknown actor %q", req.Actor)}
	}
	act := policy.Action{Kind: req.Op, IP: req.IP, TTL: req.TTL, Reason: req.Reason, Actor: req.Actor}
	ip, ttl, err := s.Policy.Check(&act)
	if err != nil {
		_ = s.Audit.Write(req.Actor, req.Op, req, "rejected: "+err.Error())
		return Response{Error: err.Error()}
	}
	key := ip.String()
	switch req.Op {
	case "block":
		expires := time.Now().Add(ttl)
		old, exists := s.blocks[key]
		if exists && !old.Expires.Before(expires) {
			break // already blocked at least this long; keep the longer block
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
			s.blocks[key] = Block{IP: key, Expires: expires, Reason: req.Reason, Actor: req.Actor}
			s.saveState()
		}
	case "unblock":
		if _, ok := s.blocks[key]; !ok {
			err = errors.New("not currently blocked by nethergate")
		} else if !s.DryRun {
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
	_ = s.Audit.Write(req.Actor, req.Op, map[string]any{"ip": key, "ttl": ttl.String(), "reason": req.Reason}, result)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, DryRun: s.DryRun}
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

package enforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Backend applies blocks somewhere: the local firewall, or a CDN in front
// of this server (behind a CDN the attacker never connects directly, so a
// local block alone would not stop them).
type Backend interface {
	Name() string
	// Apply blocks ip for ttl. ref is what this backend returned for the
	// same block before ("" if none); the returned ref is stored with the
	// block and handed back to Remove.
	Apply(ip netip.Addr, ttl time.Duration, ref, note string) (string, error)
	Remove(ip netip.Addr, ref string) error
	// NativeTTL is true when the backend expires blocks by itself.
	// Otherwise the enforcer removes them when they expire.
	NativeTTL() bool
}

// NFTBackend returns the local nftables backend of s.
func (s *Server) NFTBackend() Backend { return nftBackend{s} }

// nftBackend adds the address to the nethergate nftables set with a timeout.
type nftBackend struct{ s *Server }

func (nftBackend) Name() string    { return "nftables" }
func (nftBackend) NativeTTL() bool { return true }

func (b nftBackend) Apply(ip netip.Addr, ttl time.Duration, ref, _ string) (string, error) {
	if ref != "" {
		// "add element" does not refresh the timeout of an existing
		// element, so replace it to extend the block.
		_ = b.s.runNft("delete", "element", "inet", Table, setFor(ip), fmt.Sprintf("{ %s }", ip))
	}
	secs := max(int(ttl.Seconds()), 1)
	if err := b.s.runNft("add", "element", "inet", Table, setFor(ip), fmt.Sprintf("{ %s timeout %ds }", ip, secs)); err != nil {
		return "", err
	}
	return "set", nil
}

func (b nftBackend) Remove(ip netip.Addr, _ string) error {
	return b.s.runNft("delete", "element", "inet", Table, setFor(ip), fmt.Sprintf("{ %s }", ip))
}

// CloudflareBackend manages IP Access Rules on one zone. Cloudflare rules
// do not expire, so the enforcer deletes them when the block expires.
// Rules that already existed and were not created by nethergate are
// recorded as "external:<id>" and never deleted.
type CloudflareBackend struct {
	ZoneID string
	Token  string
	Base   string // e.g. https://api.cloudflare.com/client/v4
	Client *http.Client
}

const cfNotePrefix = "nethergate:"

func (*CloudflareBackend) Name() string    { return "cloudflare" }
func (*CloudflareBackend) NativeTTL() bool { return false }

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *CloudflareBackend) call(method, path string, body any) (cfResponse, int, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.Base+path, rd)
	if err != nil {
		return cfResponse{}, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return cfResponse{}, 0, fmt.Errorf("cloudflare: %w", err)
	}
	defer resp.Body.Close()
	var out cfResponse
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	return out, resp.StatusCode, nil
}

func cfError(r cfResponse, status int) error {
	var msgs []string
	for _, e := range r.Errors {
		msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
	}
	return fmt.Errorf("cloudflare: HTTP %d: %s", status, strings.Join(msgs, "; "))
}

func target(ip netip.Addr) string {
	if ip.Is4() {
		return "ip"
	}
	return "ip6"
}

func (c *CloudflareBackend) Apply(ip netip.Addr, _ time.Duration, ref, note string) (string, error) {
	if ref != "" {
		return ref, nil // the rule is still there; the enforcer tracks expiry
	}
	if len(note) > 200 {
		note = note[:200]
	}
	r, status, err := c.call(http.MethodPost, "/zones/"+url.PathEscape(c.ZoneID)+"/firewall/access_rules/rules", map[string]any{
		"mode":          "block",
		"configuration": map[string]string{"target": target(ip), "value": ip.String()},
		"notes":         cfNotePrefix + " " + note,
	})
	if err != nil {
		return "", err
	}
	if r.Success {
		var res struct{ ID string }
		if json.Unmarshal(r.Result, &res) != nil || res.ID == "" {
			return "", errors.New("cloudflare: rule created but no id returned")
		}
		return res.ID, nil
	}
	// A rule for this address may already exist (created by a person, or
	// by us before a lost state file). Adopt ours; never take over theirs.
	if existing, owned, ok := c.find(ip); ok {
		if owned {
			return existing, nil
		}
		return "external:" + existing, nil
	}
	return "", cfError(r, status)
}

func (c *CloudflareBackend) find(ip netip.Addr) (id string, owned, ok bool) {
	q := url.Values{"configuration.target": {target(ip)}, "configuration.value": {ip.String()}, "mode": {"block"}}
	r, _, err := c.call(http.MethodGet, "/zones/"+url.PathEscape(c.ZoneID)+"/firewall/access_rules/rules?"+q.Encode(), nil)
	if err != nil || !r.Success {
		return "", false, false
	}
	var list []struct {
		ID    string `json:"id"`
		Notes string `json:"notes"`
	}
	if json.Unmarshal(r.Result, &list) != nil || len(list) == 0 {
		return "", false, false
	}
	return list[0].ID, strings.HasPrefix(list[0].Notes, cfNotePrefix), true
}

func (c *CloudflareBackend) Remove(_ netip.Addr, ref string) error {
	if ref == "" || strings.HasPrefix(ref, "external:") {
		return nil // not ours to delete
	}
	r, status, err := c.call(http.MethodDelete, "/zones/"+url.PathEscape(c.ZoneID)+"/firewall/access_rules/rules/"+url.PathEscape(ref), nil)
	if err != nil {
		return err
	}
	if r.Success || status == http.StatusNotFound {
		return nil // already gone counts as removed
	}
	return cfError(r, status)
}

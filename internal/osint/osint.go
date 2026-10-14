// Package osint gathers *passive, public* information about a source IP:
// reverse DNS, ASN/network owner (Team Cymru), RDAP registration and abuse
// contact, Shodan InternetDB (public scan data), the Tor exit list, and
// optionally AbuseIPDB reputation.
//
// It never connects to, scans or probes the attacker's host. Every lookup
// goes to a public registry or reputation service, which is lawful in most
// jurisdictions. Do not extend this package with active techniques.
package osint

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kuramichi2010/nethergate/internal/sanitize"
)

type Result struct {
	IP           string   `json:"ip"`
	ReverseDNS   []string `json:"reverse_dns,omitempty"`
	ASN          string   `json:"asn,omitempty"`
	ASName       string   `json:"as_name,omitempty"`
	Prefix       string   `json:"bgp_prefix,omitempty"`
	Country      string   `json:"country,omitempty"`
	NetName      string   `json:"network_name,omitempty"`
	AbuseEmails  []string `json:"abuse_contacts,omitempty"`
	OpenPorts    []int    `json:"public_open_ports,omitempty"`
	Tags         []string `json:"shodan_tags,omitempty"`
	KnownVulns   []string `json:"shodan_cves,omitempty"`
	TorExit      bool     `json:"tor_exit"`
	AbuseScore   *int     `json:"abuseipdb_confidence,omitempty"`
	AbuseReports *int     `json:"abuseipdb_reports,omitempty"`
	Notes        []string `json:"notes,omitempty"`
	Errors       []string `json:"lookup_errors,omitempty"`
}

type Client struct {
	HTTP         *http.Client
	AbuseIPDBKey string

	mu      sync.Mutex
	cache   map[string]cached
	tor     map[string]bool
	torTime time.Time
}

type cached struct {
	r  Result
	at time.Time
}

func New(abuseKeyEnv string) *Client {
	c := &Client{
		HTTP:  &http.Client{Timeout: 8 * time.Second},
		cache: map[string]cached{},
	}
	if abuseKeyEnv != "" {
		c.AbuseIPDBKey = os.Getenv(abuseKeyEnv)
	}
	return c
}

const maxBody = 1 << 20

func (c *Client) getJSON(ctx context.Context, u string, hdr map[string]string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "nethergate-osint/0.1 (defensive; passive lookups)")
	req.Header.Set("Accept", "application/json")
	for k, val := range hdr {
		req.Header.Set(k, val)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return errNotFound
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(v)
}

var errNotFound = fmt.Errorf("not found")

func (c *Client) Lookup(ctx context.Context, ip netip.Addr) Result {
	key := ip.String()
	c.mu.Lock()
	if e, ok := c.cache[key]; ok && time.Since(e.at) < 6*time.Hour {
		c.mu.Unlock()
		return e.r
	}
	c.mu.Unlock()

	r := Result{IP: key}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		r.Notes = append(r.Notes, "non-public address: likely internal host, proxy misconfiguration, or spoofed header")
		return r
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	run := func(name string, f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil && err != errNotFound {
				mu.Lock()
				r.Errors = append(r.Errors, name+": "+sanitize.Untrusted(err.Error()))
				mu.Unlock()
			}
		}()
	}
	run("rdns", func() error {
		names, err := net.DefaultResolver.LookupAddr(ctx, key)
		mu.Lock()
		for _, n := range names {
			r.ReverseDNS = append(r.ReverseDNS, sanitize.Untrusted(n))
		}
		mu.Unlock()
		return err
	})
	run("cymru", func() error { return c.cymru(ctx, ip, &r, &mu) })
	run("rdap", func() error { return c.rdap(ctx, ip, &r, &mu) })
	run("internetdb", func() error { return c.internetDB(ctx, ip, &r, &mu) })
	run("tor", func() error {
		exit, err := c.isTorExit(ctx, key)
		mu.Lock()
		r.TorExit = exit
		mu.Unlock()
		return err
	})
	if c.AbuseIPDBKey != "" {
		run("abuseipdb", func() error { return c.abuseIPDB(ctx, key, &r, &mu) })
	}
	wg.Wait()
	r.Notes = append(r.Notes, interpret(&r)...)

	c.mu.Lock()
	c.cache[key] = cached{r, time.Now()}
	c.mu.Unlock()
	return r
}

func (c *Client) cymru(ctx context.Context, ip netip.Addr, r *Result, mu *sync.Mutex) error {
	var q string
	if ip.Is4() {
		b := ip.As4()
		q = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	} else {
		b := ip.As16()
		var sb strings.Builder
		for i := 15; i >= 0; i-- {
			fmt.Fprintf(&sb, "%x.%x.", b[i]&0xf, b[i]>>4)
		}
		q = sb.String() + "origin6.asn.cymru.com"
	}
	txt, err := net.DefaultResolver.LookupTXT(ctx, q)
	if err != nil || len(txt) == 0 {
		return err
	}
	// "ASN | prefix | CC | registry | date"
	f := strings.Split(txt[0], "|")
	if len(f) < 3 {
		return nil
	}
	asn := strings.Fields(strings.TrimSpace(f[0]))
	mu.Lock()
	if len(asn) > 0 {
		r.ASN = "AS" + sanitize.Untrusted(asn[0])
	}
	r.Prefix = sanitize.Untrusted(strings.TrimSpace(f[1]))
	if r.Country == "" {
		r.Country = sanitize.Untrusted(strings.TrimSpace(f[2]))
	}
	asnStr := r.ASN
	mu.Unlock()
	if asnStr == "" {
		return nil
	}
	if txt, err := net.DefaultResolver.LookupTXT(ctx, asnStr+".asn.cymru.com"); err == nil && len(txt) > 0 {
		f := strings.Split(txt[0], "|")
		mu.Lock()
		r.ASName = sanitize.Untrusted(strings.TrimSpace(f[len(f)-1]))
		mu.Unlock()
	}
	return nil
}

func (c *Client) rdap(ctx context.Context, ip netip.Addr, r *Result, mu *sync.Mutex) error {
	var v map[string]any
	if err := c.getJSON(ctx, "https://rdap.org/ip/"+url.PathEscape(ip.String()), nil, &v); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if s, ok := v["name"].(string); ok {
		r.NetName = sanitize.Untrusted(s)
	}
	if s, ok := v["country"].(string); ok && s != "" {
		r.Country = sanitize.Untrusted(s)
	}
	seen := map[string]bool{}
	var walk func(ents any)
	walk = func(ents any) {
		list, _ := ents.([]any)
		for _, e := range list {
			m, _ := e.(map[string]any)
			roles, _ := m["roles"].([]any)
			isAbuse := false
			for _, ro := range roles {
				if ro == "abuse" {
					isAbuse = true
				}
			}
			if isAbuse {
				for _, em := range vcardEmails(m["vcardArray"]) {
					if !seen[em] {
						seen[em] = true
						r.AbuseEmails = append(r.AbuseEmails, sanitize.Untrusted(em))
					}
				}
			}
			walk(m["entities"])
		}
	}
	walk(v["entities"])
	return nil
}

// vcardEmails extracts email values from a jCard: ["vcard", [[name, params, type, value], ...]].
func vcardEmails(v any) []string {
	arr, _ := v.([]any)
	if len(arr) < 2 {
		return nil
	}
	props, _ := arr[1].([]any)
	var out []string
	for _, p := range props {
		pp, _ := p.([]any)
		if len(pp) >= 4 && pp[0] == "email" {
			if s, ok := pp[3].(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func (c *Client) internetDB(ctx context.Context, ip netip.Addr, r *Result, mu *sync.Mutex) error {
	var v struct {
		Ports     []int    `json:"ports"`
		Tags      []string `json:"tags"`
		Vulns     []string `json:"vulns"`
		Hostnames []string `json:"hostnames"`
	}
	if err := c.getJSON(ctx, "https://internetdb.shodan.io/"+url.PathEscape(ip.String()), nil, &v); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	r.OpenPorts = v.Ports
	for _, t := range v.Tags {
		r.Tags = append(r.Tags, sanitize.Untrusted(t))
	}
	for i, cve := range v.Vulns {
		if i >= 15 {
			break
		}
		r.KnownVulns = append(r.KnownVulns, sanitize.Untrusted(cve))
	}
	return nil
}

func (c *Client) isTorExit(ctx context.Context, ip string) (bool, error) {
	c.mu.Lock()
	fresh := c.tor != nil && time.Since(c.torTime) < 2*time.Hour
	c.mu.Unlock()
	if !fresh {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.torproject.org/torbulkexitlist", nil)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		// An error page must not be cached for 2h as "no exit is Tor".
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("%s: HTTP %d", req.URL.Host, resp.StatusCode)
		}
		set := map[string]bool{}
		sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
		for sc.Scan() {
			set[strings.TrimSpace(sc.Text())] = true
		}
		if err := sc.Err(); err != nil {
			return false, err
		}
		c.mu.Lock()
		c.tor, c.torTime = set, time.Now()
		c.mu.Unlock()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tor[ip], nil
}

func (c *Client) abuseIPDB(ctx context.Context, ip string, r *Result, mu *sync.Mutex) error {
	var v struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
			TotalReports         int `json:"totalReports"`
		} `json:"data"`
	}
	u := "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=" + url.QueryEscape(ip)
	if err := c.getJSON(ctx, u, map[string]string{"Key": c.AbuseIPDBKey}, &v); err != nil {
		return err
	}
	mu.Lock()
	r.AbuseScore, r.AbuseReports = &v.Data.AbuseConfidenceScore, &v.Data.TotalReports
	mu.Unlock()
	return nil
}

func interpret(r *Result) []string {
	var n []string
	if r.TorExit {
		n = append(n, "Tor exit node: the real origin is hidden; blocking the IP stops this path only")
	}
	for _, t := range r.Tags {
		switch t {
		case "vpn", "proxy":
			n = append(n, "commercial VPN/proxy: source IP is not the attacker's own machine")
		case "cloud":
			n = append(n, "cloud-hosted: likely rented or compromised VPS; report to the provider's abuse contact")
		case "compromised", "malware":
			n = append(n, "host itself looks compromised: may be a botnet node, not the operator")
		}
	}
	if len(r.KnownVulns) > 0 {
		n = append(n, "public scan data lists known CVEs on this host: consistent with a hijacked device (botnet)")
	}
	return n
}

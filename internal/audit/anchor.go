package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// AnchorMarker prefixes anchor lines in the process log (journald). Ship
// the journal to a remote syslog/SIEM and those lines become anchors an
// attacker on this host cannot rewrite.
const AnchorMarker = "NETHERGATE-ANCHOR"

// Publisher announces chain heads outside the audit file itself.
type Publisher struct {
	URL  string // optional HTTPS collector
	HTTP *http.Client

	mu   sync.Mutex
	last map[string]int
}

// Publish logs (and optionally POSTs) the head of file if it changed.
func (p *Publisher) Publish(path string, n int, hash string) {
	if n == 0 {
		return
	}
	file := filepath.Base(path)
	p.mu.Lock()
	if p.last == nil {
		p.last = map[string]int{}
	}
	if p.last[file] == n {
		p.mu.Unlock()
		return
	}
	p.last[file] = n
	p.mu.Unlock()
	log.Printf("%s file=%s n=%d hash=%s", AnchorMarker, file, n, hash)
	if p.URL == "" {
		return
	}
	go func() {
		body, _ := json.Marshal(map[string]any{"file": file, "n": n, "hash": hash, "time": time.Now().UTC()})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		c := p.HTTP
		if c == nil {
			c = http.DefaultClient
		}
		resp, err := c.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) { // do not log the collector URL (may hold a token)
				err = ue.Err
			}
			log.Printf("anchor publish: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

// PublishFile publishes the current head of the log at path.
func (p *Publisher) PublishFile(path string) {
	n, h, err := HeadOf(path)
	if err == nil {
		p.Publish(path, n, h)
	}
}

var anchorLine = regexp.MustCompile(AnchorMarker + ` file=(\S+) n=(\d+) hash=([0-9a-f]{64})`)

// ParseAnchors reads anchor lines (e.g. `journalctl -u 'nethergate-*'`
// output, or a SIEM export) and groups them by log file name.
func ParseAnchors(r io.Reader) (map[string][]Anchor, error) {
	out := map[string][]Anchor{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		m := anchorLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		out[m[1]] = append(out[m[1]], Anchor{N: n, Hash: m[3]})
	}
	return out, sc.Err()
}

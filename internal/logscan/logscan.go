// Package logscan reads configured log files into a detect.Analyzer. It is
// shared by the watch daemon, the MCP server, the CLI and the enforcer
// (which re-derives incidents from the logs instead of trusting callers).
package logscan

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/detect"
	"github.com/kuramichi2010/nethergate/internal/event"
	"github.com/kuramichi2010/nethergate/internal/playbook"
)

// Scan reads the tail (up to MaxScanBytes) of every configured log and
// returns an analyzer populated with events inside the window. A log that
// cannot be opened is reported and skipped, so one missing file (e.g. no
// auth.log on a journald-only host) does not disable every MCP tool; it
// is an error only if no log at all could be read.
func Scan(cfg *config.Config, rules []*playbook.Rule, now time.Time) (*detect.Analyzer, error) {
	return scan(cfg, rules, now, netip.Addr{})
}

// ScanIP is Scan restricted to one source address. The enforcer uses it to
// re-derive an incident from the logs itself instead of trusting the caller.
func ScanIP(cfg *config.Config, rules []*playbook.Rule, ip netip.Addr, now time.Time) (*detect.Analyzer, error) {
	return scan(cfg, rules, now, ip)
}

func scan(cfg *config.Config, rules []*playbook.Rule, now time.Time, only netip.Addr) (*detect.Analyzer, error) {
	a := detect.NewAnalyzer(cfg.Window.D())
	a.Rules = rules
	a.Proxies = cfg.ProxyPrefixes
	since := now.Add(-cfg.Window.D())
	var firstErr error
	opened := 0
	for _, src := range cfg.Logs {
		f, err := os.Open(src.Path)
		if err != nil {
			log.Printf("scan %s: %v", src.Path, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		opened++
		var r io.Reader = f
		if st, err := f.Stat(); err == nil && st.Size() > cfg.MaxScanBytes {
			_, _ = f.Seek(st.Size()-cfg.MaxScanBytes, io.SeekStart)
			// We landed mid-line: drop the fragment instead of parsing it.
			br := bufio.NewReaderSize(f, 64<<10)
			_, _ = br.ReadString('\n')
			r = br
		}
		feedOnly(a, src.Format, r, since, now, only)
		f.Close()
	}
	if opened == 0 && firstErr != nil {
		return nil, firstErr
	}
	return a, nil
}

func Feed(a *detect.Analyzer, format string, r io.Reader, since, now time.Time) int64 {
	return feedOnly(a, format, r, since, now, netip.Addr{})
}

// feedOnly parses lines into a; if only is valid, other sources are skipped
// (a cheap substring test first, then the parsed address decides).
func feedOnly(a *detect.Analyzer, format string, r io.Reader, since, now time.Time, only netip.Addr) int64 {
	var needle []byte
	if only.IsValid() {
		needle = []byte(only.String())
	}
	br := bufio.NewReaderSize(r, 64<<10)
	var n int64
	for {
		// ReadSlice returns a view into the buffer: lines are only copied
		// into a string when they are actually parsed.
		line, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			// A line longer than the buffer (64 KiB) is never parsed: skip it.
			skipped := int64(len(line))
			for err == bufio.ErrBufferFull {
				line, err = br.ReadSlice('\n')
				skipped += int64(len(line))
			}
			if err != nil {
				return n // unterminated: re-read on the next poll
			}
			n += skipped
			continue
		}
		if len(line) > 0 && line[len(line)-1] == '\n' {
			n += int64(len(line))
			if len(line) <= 16<<10 && (needle == nil || bytes.Contains(line, needle)) { // ignore absurd lines rather than buffer them
				if ev, ok := event.Parse(format, string(line[:len(line)-1]), now); ok && !ev.Time.Before(since) {
					// Behind a CDN the peer is the CDN: find the real client,
					// and never score the CDN itself.
					if !ev.ResolveClient(a.Proxies) {
						a.ProxyUnresolved++
					} else if needle == nil || ev.IP == only {
						a.Add(ev)
					}
				}
			}
		}
		if err != nil {
			return n // partial trailing line is re-read on the next poll
		}
	}
}

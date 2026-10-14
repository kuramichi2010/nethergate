// Package watch reads configured logs, feeds the analyzer, applies
// rule-based blocks and hands risky incidents to an AI for triage.
package watch

import (
	"bufio"
	"io"
	"log"
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
	a := detect.NewAnalyzer(cfg.Window.D())
	a.Rules = rules
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
		feed(a, src.Format, r, since, now)
		f.Close()
	}
	if opened == 0 && firstErr != nil {
		return nil, firstErr
	}
	return a, nil
}

func feed(a *detect.Analyzer, format string, r io.Reader, since, now time.Time) int64 {
	br := bufio.NewReaderSize(r, 64<<10)
	var n int64
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			n += int64(len(line))
			if len(line) <= 16<<10 { // ignore absurd lines rather than buffer them
				if ev, ok := event.Parse(format, line[:len(line)-1], now); ok && !ev.Time.Before(since) {
					a.Add(ev)
				}
			}
		}
		if err != nil {
			return n // partial trailing line is re-read on the next poll
		}
	}
}

// tailer follows one file across rotation (inode change or truncation).
type tailer struct {
	src    config.LogSource
	f      *os.File
	ino    uint64
	offset int64
}

func (t *tailer) poll(a *detect.Analyzer, now time.Time) error {
	st, err := os.Stat(t.src.Path)
	if err != nil {
		return err
	}
	ino := inode(st)
	if t.f == nil || ino != t.ino || st.Size() < t.offset {
		if t.f != nil {
			if ino != t.ino { // rotated: read what was appended before the rename
				if _, err := t.f.Seek(t.offset, io.SeekStart); err == nil {
					feed(a, t.src.Format, t.f, now.Add(-time.Hour), now)
				}
			}
			t.f.Close()
		}
		f, err := os.Open(t.src.Path)
		if err != nil {
			return err
		}
		start := int64(0)
		if t.f == nil { // first open: start at end, history is handled by Scan
			start = st.Size()
		}
		t.f, t.ino, t.offset = f, ino, start
	}
	if _, err := t.f.Seek(t.offset, io.SeekStart); err != nil {
		return err
	}
	t.offset += feed(a, t.src.Format, t.f, now.Add(-time.Hour), now)
	return nil
}

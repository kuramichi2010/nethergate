// Package watch reads configured logs, feeds the analyzer, applies
// rule-based blocks and hands risky incidents to an AI for triage.
package watch

import (
	"io"
	"os"
	"time"

	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/detect"
	"github.com/kuramichi2010/nethergate/internal/logscan"
)

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
					logscan.Feed(a, t.src.Format, t.f, now.Add(-time.Hour), now)
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
	t.offset += logscan.Feed(a, t.src.Format, t.f, now.Add(-time.Hour), now)
	return nil
}

// Package forward ships every audit record, plus chain-head anchors, to a
// remote syslog server or SIEM, so evidence survives a compromise of this
// host.
//
// The audit files themselves are the spool: a per-file offset is advanced
// only after every sink accepted the batch, so an outage loses nothing and
// needs no extra disk. Delivery is at-least-once; each event carries the
// file name and record number so the SIEM can de-duplicate.
//
// A file that shrinks or is replaced is reported as a tamper event before
// forwarding restarts from its beginning.
package forward

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Event is one line sent to the SIEM.
type Event struct {
	Type   string          `json:"type"` // "audit" | "anchor" | "tamper"
	Time   time.Time       `json:"time"`
	Host   string          `json:"host"`
	File   string          `json:"file"`
	N      int             `json:"n,omitempty"`    // record number in the file (1-based)
	Hash   string          `json:"hash,omitempty"` // anchor: chain head after record N
	Record json.RawMessage `json:"record,omitempty"`
	Detail string          `json:"detail,omitempty"`
}

// Sink delivers a batch; it must return an error unless every event was accepted.
type Sink interface {
	Send(events []Event) error
	Name() string
}

type fileState struct {
	Offset int64  `json:"offset"`
	N      int    `json:"n"`
	Ino    uint64 `json:"ino"`
	Hash   string `json:"hash"`
}

// Forwarder tails a fixed set of audit files.
type Forwarder struct {
	Files     []string
	Sinks     []Sink
	StatePath string
	Host      string
	MaxBatch  int

	mu      sync.Mutex
	state   map[string]*fileState
	backoff time.Duration
	nextTry time.Time
	// Stats for metrics.
	Sent     map[string]int64 // events per file
	Errors   int64
	LagBytes map[string]int64
	Tampers  int64
}

func (f *Forwarder) load() {
	f.state = map[string]*fileState{}
	f.Sent = map[string]int64{}
	f.LagBytes = map[string]int64{}
	b, err := os.ReadFile(f.StatePath)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &f.state)
	if f.state == nil {
		f.state = map[string]*fileState{}
	}
}

func (f *Forwarder) save() {
	b, _ := json.Marshal(f.state)
	tmp := f.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err == nil {
		_ = os.Rename(tmp, f.StatePath)
	}
}

// Run forwards until stop is closed, polling every interval.
func (f *Forwarder) Run(interval time.Duration, stop <-chan struct{}) {
	f.mu.Lock()
	f.load()
	f.mu.Unlock()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		f.Step(time.Now())
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

// Step forwards whatever is new. Exported for tests.
func (f *Forwarder) Step(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == nil {
		f.load()
	}
	if now.Before(f.nextTry) {
		return
	}
	for _, path := range f.Files {
		if err := f.forwardFile(path, now); err != nil {
			f.Errors++
			if f.backoff == 0 {
				f.backoff = 5 * time.Second
			} else {
				f.backoff = min(f.backoff*2, 5*time.Minute)
			}
			f.nextTry = now.Add(f.backoff)
			log.Printf("forward: %v (retry in %s)", err, f.backoff)
			return
		}
	}
	f.backoff = 0
}

func inode(fi os.FileInfo) uint64 {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return 0
}

func (f *Forwarder) send(events []Event) error {
	for _, s := range f.Sinks {
		if err := s.Send(events); err != nil {
			return fmt.Errorf("%s: %w", s.Name(), err)
		}
	}
	return nil
}

func (f *Forwarder) forwardFile(path string, now time.Time) error {
	name := filepath.Base(path)
	st := f.state[name]
	if st == nil {
		st = &fileState{}
		f.state[name] = st
	}
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		if st.Offset > 0 {
			ev := Event{Type: "tamper", Time: now, Host: f.Host, File: name, N: st.N, Hash: st.Hash,
				Detail: fmt.Sprintf("audit file disappeared after %d forwarded records", st.N)}
			if err := f.send([]Event{ev}); err != nil {
				return err
			}
			f.Tampers++
			*st = fileState{}
			f.save()
		}
		return nil
	}
	if err != nil {
		return err
	}
	if st.Offset > 0 && (fi.Size() < st.Offset || (st.Ino != 0 && inode(fi) != st.Ino)) {
		ev := Event{Type: "tamper", Time: now, Host: f.Host, File: name, N: st.N, Hash: st.Hash,
			Detail: fmt.Sprintf("audit file shrank or was replaced (had %d bytes / %d records forwarded, now %d bytes)", st.Offset, st.N, fi.Size())}
		if err := f.send([]Event{ev}); err != nil {
			return err
		}
		f.Tampers++
		*st = fileState{}
	}
	st.Ino = inode(fi)
	f.LagBytes[name] = fi.Size() - st.Offset
	for fi.Size() > st.Offset {
		n, err := f.batch(path, name, st, now)
		if err != nil {
			return err
		}
		if n == 0 {
			break // only a partial trailing line
		}
	}
	f.LagBytes[name] = fi.Size() - st.Offset
	return nil
}

// batch sends up to MaxBatch complete records starting at st.Offset.
func (f *Forwarder) batch(path, name string, st *fileState, now time.Time) (int, error) {
	fh, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	if _, err := fh.Seek(st.Offset, io.SeekStart); err != nil {
		return 0, err
	}
	max := f.MaxBatch
	if max <= 0 {
		max = 500
	}
	br := bufio.NewReaderSize(fh, 64<<10)
	var events []Event
	var consumed int64
	n, hash := st.N, st.Hash
	for len(events) < max {
		line, err := br.ReadBytes('\n')
		if err != nil {
			break // EOF or partial line: wait for the writer
		}
		consumed += int64(len(line))
		line = line[:len(line)-1]
		n++
		ev := Event{Type: "audit", Time: now, Host: f.Host, File: name, N: n}
		var rec struct {
			Hash string `json:"hash"`
		}
		if json.Valid(line) {
			ev.Record = json.RawMessage(append([]byte(nil), line...))
			if json.Unmarshal(line, &rec) == nil && rec.Hash != "" {
				hash = rec.Hash
			}
		} else {
			ev.Detail = "unparseable audit line"
			ev.Record, _ = json.Marshal(string(line))
		}
		events = append(events, ev)
	}
	if len(events) == 0 {
		return 0, nil
	}
	events = append(events, Event{Type: "anchor", Time: now, Host: f.Host, File: name, N: n, Hash: hash})
	if err := f.send(events); err != nil {
		return 0, err
	}
	st.Offset += consumed
	st.N, st.Hash = n, hash
	f.Sent[name] += int64(len(events) - 1)
	f.save()
	return len(events) - 1, nil
}

// Stats is a snapshot for metrics.
type Stats struct {
	Sent     map[string]int64
	LagBytes map[string]int64
	Errors   int64
	Tampers  int64
}

func (f *Forwarder) Stats() Stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := Stats{Sent: map[string]int64{}, LagBytes: map[string]int64{}, Errors: f.Errors, Tampers: f.Tampers}
	for k, v := range f.Sent {
		s.Sent[k] = v
	}
	for k, v := range f.LagBytes {
		s.LagBytes[k] = v
	}
	return s
}

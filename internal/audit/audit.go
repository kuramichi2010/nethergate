// Package audit writes a tamper-evident, hash-chained JSONL log of every
// decision and action. Each record includes the SHA-256 of the previous
// one, so deleting or editing a line breaks verification.
//
// Several processes may append to the same file (e.g. two MCP sessions), so
// every write takes an exclusive flock and re-reads the chain head if
// another writer appended since our last write.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

type Record struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail any       `json:"detail,omitempty"`
	Result string    `json:"result"`
	Prev   string    `json:"prev"`
	Hash   string    `json:"hash"`
}

type Log struct {
	mu   sync.Mutex
	path string
	last string
	n    int   // number of records in the chain
	size int64 // file size right after our last read/write of the head
}

// Head returns the record count and hash of the newest record: an anchor
// value that, once published elsewhere, pins the log up to that point.
func (l *Log) Head() (int, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n, l.last
}

// HeadOf reads the current head of the log at path.
func HeadOf(path string) (int, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	l := &Log{path: path}
	if err := l.readHead(f); err != nil {
		return 0, "", err
	}
	return l.n, l.last, nil
}

// Anchor is a published (count, hash) pair for one log file.
type Anchor struct {
	N    int    `json:"n"`
	Hash string `json:"hash"`
}

// VerifyAnchors checks the chain and that record N of each anchor still has
// the published hash. A log truncated below N, or rewritten from an
// earlier point (even with a valid new chain), fails.
func VerifyAnchors(path string, anchors []Anchor) (int, error) {
	n, err := Verify(path)
	if err != nil {
		return n, err
	}
	want := map[int]string{}
	for _, a := range anchors {
		if a.N > n {
			return n, fmt.Errorf("anchor at record %d but the log has only %d records (truncated)", a.N, n)
		}
		want[a.N] = a.Hash
	}
	f, err := os.Open(path)
	if err != nil {
		return n, err
	}
	defer f.Close()
	i := 0
	err = eachLine(f, func(line []byte) error {
		i++
		h, ok := want[i]
		if !ok {
			return nil
		}
		var r Record
		_ = json.Unmarshal(line, &r)
		if r.Hash != h {
			return fmt.Errorf("record %d does not match the published anchor (log rewritten)", i)
		}
		return nil
	})
	return n, err
}

func Open(path string) (*Log, error) {
	l := &Log{path: path}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := l.readHead(f); err != nil {
		return nil, err
	}
	return l, nil
}

// readHead scans f from the start and records the hash of the last record.
func (l *Log) readHead(f *os.File) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	l.last, l.size, l.n = "", 0, 0
	err := eachLine(f, func(line []byte) error {
		var r Record
		if json.Unmarshal(line, &r) == nil {
			l.last = r.Hash
			l.n++
		}
		return nil
	})
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		return err
	}
	l.size = st.Size()
	return nil
}

// eachLine calls fn for every newline-terminated (or final) line, with no
// line length limit: a single oversized record must not make the whole log
// unreadable (which would stop the services from starting).
func eachLine(r io.Reader, fn func([]byte) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if ferr := fn(bytes.TrimSuffix(line, []byte("\n"))); ferr != nil {
				return ferr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func hashOf(r Record) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (l *Log) Write(actor, action string, detail any, result string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := Record{Time: time.Now().UTC(), Actor: actor, Action: action, Detail: detail, Result: result, Prev: l.last}
	// round-trip detail so the hash is computed over exactly what is stored
	if b, err := json.Marshal(r.Detail); err == nil {
		var v any
		_ = json.Unmarshal(b, &v)
		r.Detail = v
	}
	r.Hash = hashOf(r)
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() != l.size { // another process appended: continue its chain
		if err := l.readHead(f); err != nil {
			return err
		}
		r.Prev = l.last
		r.Hash = hashOf(r)
		if b, err = json.Marshal(r); err != nil {
			return err
		}
	}
	n, err := f.Write(append(b, '\n'))
	if err != nil {
		return err
	}
	l.last = r.Hash
	l.n++
	l.size += int64(n)
	return nil
}

// Verify checks the whole chain and returns the number of valid records.
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	prev, n := "", 0
	err = eachLine(f, func(line []byte) error {
		n++
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		if r.Prev != prev {
			return fmt.Errorf("line %d: chain broken (record removed or reordered)", n)
		}
		if hashOf(r) != r.Hash {
			return fmt.Errorf("line %d: hash mismatch (record modified)", n)
		}
		prev = r.Hash
		return nil
	})
	if err != nil {
		return n - 1, err
	}
	return n, nil
}

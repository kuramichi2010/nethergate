package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"time":"2026-10-14T00:00:00Z","actor":"ai","action":"block","result":"ok","prev":"","hash":"x"}` + "\n"))
	f.Add([]byte("\n\n{"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "a.jsonl")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = Verify(p)
		_, _ = VerifyAnchors(p, []Anchor{{N: 1, Hash: "x"}})
		_, _, _ = HeadOf(p)
		// Appending to any existing file must not panic either.
		if l, err := Open(p); err == nil {
			_ = l.Write("ai", "x", nil, "ok")
		}
		_, _ = ParseAnchors(bytes.NewReader(b))
	})
}

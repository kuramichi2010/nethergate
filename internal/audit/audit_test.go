package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainDetectsTampering(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	l, _ := Open(p)
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if err := l.Write("ai", "block", map[string]any{"ip": ip, "ttl": "1h"}, "ok"); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := Verify(p); err != nil || n != 3 {
		t.Fatalf("clean log: %d %v", n, err)
	}
	// reopening continues the chain
	l2, _ := Open(p)
	_ = l2.Write("human", "unblock", nil, "ok")
	if n, err := Verify(p); err != nil || n != 4 {
		t.Fatalf("reopened: %d %v", n, err)
	}

	b, _ := os.ReadFile(p)
	edited := strings.Replace(string(b), "198.51.100.2", "198.51.100.9", 1)
	_ = os.WriteFile(p, []byte(edited), 0o600)
	if _, err := Verify(p); err == nil {
		t.Fatal("edit not detected")
	}

	lines := strings.SplitAfter(string(b), "\n")
	_ = os.WriteFile(p, []byte(lines[0]+lines[2]), 0o600)
	if _, err := Verify(p); err == nil {
		t.Fatal("deletion not detected")
	}
}

func TestConcurrentWritersKeepOneChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	l1, _ := Open(p)
	l2, _ := Open(p) // e.g. two MCP sessions
	for i := 0; i < 3; i++ {
		_ = l1.Write("ai", "x", nil, "ok")
		_ = l2.Write("ai", "y", nil, "ok")
	}
	if n, err := Verify(p); err != nil || n != 6 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestHugeRecordStaysReadable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	l, _ := Open(p)
	_ = l.Write("ai", "tool:save_report", map[string]any{"markdown": strings.Repeat("<", 1<<20)}, "ok")
	l2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Write("ai", "x", nil, "ok")
	if n, err := Verify(p); err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestAnchorsDetectTruncationAndRewrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "enforcer-audit.jsonl")
	l, _ := Open(p)
	for i := 0; i < 5; i++ {
		_ = l.Write("ai", "block", map[string]any{"i": i}, "ok")
	}
	n, h := l.Head()
	var buf strings.Builder
	fmt.Fprintf(&buf, "Oct 14 host nethergate[1]: %s file=enforcer-audit.jsonl n=%d hash=%s\n", AnchorMarker, n, h)
	anchors, err := ParseAnchors(strings.NewReader(buf.String()))
	if err != nil || len(anchors["enforcer-audit.jsonl"]) != 1 {
		t.Fatalf("%v %v", anchors, err)
	}
	a := anchors["enforcer-audit.jsonl"]
	if _, err := VerifyAnchors(p, a); err != nil {
		t.Fatal(err)
	}
	// Attacker drops the last two records: the chain itself is still valid...
	b, _ := os.ReadFile(p)
	lines := strings.SplitAfter(string(b), "\n")
	os.WriteFile(p, []byte(strings.Join(lines[:3], "")), 0o600)
	if _, err := Verify(p); err != nil {
		t.Fatalf("truncated chain should still self-verify: %v", err)
	}
	// ...but not against the published anchor.
	if _, err := VerifyAnchors(p, a); err == nil {
		t.Fatal("truncation not detected")
	}
	// Attacker rebuilds a fresh, internally valid chain of the same length.
	os.Remove(p)
	l2, _ := Open(p)
	for i := 0; i < 5; i++ {
		_ = l2.Write("human", "noop", nil, "ok")
	}
	if _, err := VerifyAnchors(p, a); err == nil {
		t.Fatal("rewritten log not detected")
	}
}

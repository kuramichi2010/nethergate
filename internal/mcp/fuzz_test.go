package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func FuzzServe(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"block_ip","arguments":{"ip":"203.0.113.5","reason":"x"}}}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"propose_rule","arguments":{"name":"n","description":"d","handling":"h","path_regex":"(","score":1,"example_ip":"203.0.113.77"}}}`)
	f.Add(`{"jsonrpc":"2.0","id":"x","method":"initialize","params":{"protocolVersion":7}}`)
	f.Add(`not json`)
	f.Fuzz(func(t *testing.T, line string) {
		s, sent := setup(t)
		var out bytes.Buffer
		if err := s.Serve(context.Background(), strings.NewReader(line+"\n"), &out); err != nil {
			return // oversize line etc.
		}
		dec := json.NewDecoder(&out)
		for dec.More() {
			var m map[string]any
			if err := dec.Decode(&m); err != nil {
				t.Fatalf("server wrote invalid JSON: %v", err)
			}
		}
		// Whatever the input, the AI may only ever reach the enforcer
		// for the one source that attacked in the fixture.
		for _, r := range *sent {
			if r.Op == "block" && r.IP != "203.0.113.5" {
				t.Fatalf("block of %s reached the enforcer", r.IP)
			}
		}
	})
}

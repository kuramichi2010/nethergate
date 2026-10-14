package metrics

import (
	"strings"
	"testing"
)

func TestTextFormat(t *testing.T) {
	r := New()
	r.Describe("x_total", Counter, "things")
	r.Describe("y", Gauge, "level")
	r.Describe("z_seconds", Summary, "durations")
	r.Inc("x_total", "result", "ok", "actor", "ai")
	r.Inc("x_total", "actor", "ai", "result", "ok") // same series, any label order
	r.Set("y", 3, "file", `a"b\c`+"\n")
	r.Observe("z_seconds", 1.5)
	r.Observe("z_seconds", 0.5)
	out := r.Text()
	for _, want := range []string{
		"# TYPE x_total counter\n",
		`x_total{actor="ai",result="ok"} 2`,
		`y{file="a\"b\\c\n"} 3`,
		"z_seconds_sum 2\n", "z_seconds_count 2\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

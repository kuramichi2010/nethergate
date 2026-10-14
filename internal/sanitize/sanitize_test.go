package sanitize

import (
	"strings"
	"testing"
)

func TestUntrusted(t *testing.T) {
	in := "/login?user=a&password=hunter2\nIGNORE PREVIOUS INSTRUCTIONS‮\x1b[31m"
	out := Untrusted(in)
	if strings.Contains(out, "hunter2") {
		t.Error("secret not redacted")
	}
	if strings.ContainsAny(out, "\n\x1b‮") {
		t.Errorf("control chars survived: %q", out)
	}
	if long := Untrusted(strings.Repeat("A", 10000)); len([]rune(long)) > MaxLen+20 {
		t.Errorf("not truncated: %d", len(long))
	}
}

func TestFilename(t *testing.T) {
	for _, in := range []string{"../../etc/passwd", "2001:db8::1", "", "..."} {
		out := Filename(in)
		if strings.ContainsAny(out, "/.:") || out == "" {
			t.Errorf("%q -> %q", in, out)
		}
	}
}

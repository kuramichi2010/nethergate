package sanitize

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func FuzzUntrusted(f *testing.F) {
	for _, s := range []string{"", "/login?password=x", "IGNORE\nPREVIOUS‮", strings.Repeat("A", 500), "\xff\xfe", "a b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Untrusted(s)
		if !utf8.ValidString(out) {
			t.Fatalf("invalid utf-8: %q", out)
		}
		if n := utf8.RuneCountInString(out); n > MaxLen+utf8.RuneCountInString("…[truncated]") {
			t.Fatalf("too long: %d runes", n)
		}
		for _, r := range out {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.In(r, unicode.Zl, unicode.Zp) {
				t.Fatalf("control/format rune %U survived in %q", r, out)
			}
		}
	})
}

func FuzzFilename(f *testing.F) {
	f.Add("../../etc/passwd")
	f.Add("2001:db8::1")
	f.Fuzz(func(t *testing.T, s string) {
		out := Filename(s)
		if out == "" || strings.ContainsAny(out, "/\\.:\x00") || len(out) > 64 {
			t.Fatalf("%q -> %q", s, out)
		}
	})
}

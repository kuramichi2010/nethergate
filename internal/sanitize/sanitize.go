// Package sanitize neutralises attacker-controlled strings (paths, user
// agents, usernames) before they are shown to an AI model or a human.
//
// Log content is written by the attacker. Anything that reaches the model
// must be treated as untrusted data: it is stripped of control characters,
// secrets are redacted, and length is capped so a payload cannot smuggle a
// long instruction block into the model's context.
package sanitize

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxLen = 160

var secretParam = regexp.MustCompile(`(?i)((?:pass(?:word|wd)?|pwd|token|secret|api[_-]?key|key|auth|session|sid|jwt|code)=)[^&\s]*`)
var bearer = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`)

// Untrusted cleans s for display. The result is printable, single-line,
// secret-redacted and at most MaxLen runes (plus an ellipsis marker).
func Untrusted(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = secretParam.ReplaceAllString(s, "${1}[REDACTED]")
	s = bearer.ReplaceAllString(s, "${1}[REDACTED]")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= MaxLen {
			b.WriteString("…[truncated]")
			break
		}
		switch {
		case r == '\n' || r == '\r' || r == '\t', unicode.In(r, unicode.Zl, unicode.Zp): // U+2028/2029 break lines too
			b.WriteByte(' ')
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r): // includes bidi overrides / zero-width
			b.WriteString("�")
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

// Filename returns a safe file-name component (no separators, no dots at start).
func Filename(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			break
		}
		if r < utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.TrimLeft(b.String(), "_")
	if out == "" {
		return "x"
	}
	return out
}

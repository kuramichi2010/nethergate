package detect

import (
	"regexp"
	"testing"
)

// The original case-insensitive patterns: the folded, lower-case versions
// used in production must match exactly the same inputs.
var reference = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(union(\s|\+|/\*\*/)+select|'\s*or\s*'?\d|\bor\s+1=1|sleep\(\d|benchmark\(|information_schema|extractvalue\(|waitfor\s+delay)`),
	regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self/|win\.ini|boot\.ini)`),
	regexp.MustCompile(`(?i)(\$\{jndi:|;\s*(wget|curl|bash|sh)\s|\|\s*(wget|curl)|/bin/(ba)?sh|cmd\.exe|powershell|\$\(|base64_decode\(|eval\(|system\(|shell_exec)`),
	regexp.MustCompile(`(?i)(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+=)`),
	regexp.MustCompile(`(?i)(/\.env|/\.git/|/\.aws/|/\.ssh/|/wp-config\.php|/config\.php\.bak|\.sql(\.gz)?$|/backup\.(zip|tar)|/\.DS_Store|/id_rsa|/server-status)`),
	regexp.MustCompile(`(?i)(/wp-login\.php|/wp-admin|/phpmyadmin|/pma/|/adminer|/xmlrpc\.php|/manager/html|/actuator|/solr/admin|/console/)`),
	regexp.MustCompile(`(?i)(/cgi-bin/.*\.(sh|cgi)|/vendor/phpunit/.*eval-stdin|/boaform/|/HNAP1|/GponForm|/\.well-known/.*\.php|/autodiscover/autodiscover\.json|/ecp/|/owa/auth/x\.js|/remote/fgt_lang|/dana-na/)`),
}
var refScanner = regexp.MustCompile(`(?i)(sqlmap|nikto|nuclei|masscan|zgrab|gobuster|ffuf|dirbuster|wpscan|nmap|acunetix|netsparker|burp|hydra|feroxbuster|httpx|interactsh)`)
var refBot = regexp.MustCompile(`(?i)(python-requests|python-httpx|aiohttp|go-http-client|libwww-perl|curl/|wget/|okhttp|java/|node-fetch|axios|headless)`)

func FuzzFoldedSignaturesMatchCaseInsensitive(f *testing.F) {
	for _, s := range []string{"/?id=1 UNION SELECT 1", "/Kelvin", "/.DS_Store", "/HNAP1/", "UNION ſELECT", "/?q=<SVG ONLOAD=x>",
		"SQLMap/1.8", "Python-Requests/2", "/WIN.INI", "ſleep(1", "/İd_rsa"} {
		f.Add(s)
	}
	a := NewAnalyzer(0)
	f.Fuzz(func(t *testing.T, s string) {
		got := a.pathCategories(s)
		for i, re := range reference {
			if want := re.MatchString(s); want != (got&(1<<i) != 0) {
				t.Fatalf("%s on %q: folded=%v, (?i)=%v", pathSignatures[i].Category, s, !want, want)
			}
		}
		k := a.uaKind(s)
		want := uint8(0)
		if refScanner.MatchString(s) {
			want = 1
		} else if refBot.MatchString(s) {
			want = 2
		}
		if k != want {
			t.Fatalf("ua %q: folded=%d, (?i)=%d", s, k, want)
		}
	})
}

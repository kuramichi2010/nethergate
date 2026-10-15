package detect

import "testing"

func TestFoldEdgeCases(t *testing.T) {
	a := NewAnalyzer(0)
	for _, s := range []string{"xKor 1=1", "Kor 1=1", "/?q=<svg onK=1", "/?q=<svg onſ=1", "ſ' or 1"} {
		got := a.pathCategories(s)
		for i, re := range reference {
			if want := re.MatchString(s); want != (got&(1<<i) != 0) {
				t.Errorf("%s on %q: folded=%v, (?i)=%v", pathSignatures[i].Category, s, !want, want)
			}
		}
	}
}

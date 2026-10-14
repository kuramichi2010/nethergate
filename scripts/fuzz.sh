#!/bin/sh
# Run every Go fuzz target for the given time (default 30s).
# A failing input is saved under <pkg>/testdata/fuzz/<Target>/ and then
# replayed by plain `go test` forever after: commit it with the fix.
set -eu
t="${1:-30s}"
for f in $(grep -rl --include='*_test.go' '^func Fuzz' internal); do
	pkg="./$(dirname "$f")"
	for target in $(sed -n 's/^func \(Fuzz[A-Za-z0-9_]*\).*/\1/p' "$f"); do
		echo "== $pkg $target ($t)"
		go test "$pkg" -run '^$' -fuzz "^${target}\$" -fuzztime "$t"
	done
done

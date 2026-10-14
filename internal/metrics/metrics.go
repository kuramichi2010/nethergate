// Package metrics is a small, dependency-free Prometheus registry that
// writes the text exposition format (version 0.0.4). OpenTelemetry users
// scrape it with the collector's prometheus receiver.
//
// Labels must have low cardinality: never put an IP address in a label.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type kind string

const (
	Counter kind = "counter"
	Gauge   kind = "gauge"
	Summary kind = "summary"
)

type family struct {
	kind   kind
	help   string
	values map[string]float64 // rendered label set -> value
}

type Registry struct {
	mu   sync.Mutex
	fams map[string]*family
}

func New() *Registry { return &Registry{fams: map[string]*family{}} }

// Describe registers a metric. Metrics must be described before use.
func (r *Registry) Describe(name string, k kind, help string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.fams[name]; !ok {
		r.fams[name] = &family{kind: k, help: help, values: map[string]float64{}}
	}
}

var escaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// labels renders k1, v1, k2, v2... as {k1="v1",k2="v2"} (sorted by key).
func labels(kv []string) string {
	if len(kv) == 0 {
		return ""
	}
	type pair struct{ k, v string }
	var ps []pair
	for i := 0; i+1 < len(kv); i += 2 {
		ps = append(ps, pair{kv[i], kv[i+1]})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].k < ps[j].k })
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range ps {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, p.k, escaper.Replace(p.v))
	}
	b.WriteByte('}')
	return b.String()
}

func (r *Registry) fam(name string) *family {
	f, ok := r.fams[name]
	if !ok {
		panic("metrics: " + name + " used before Describe")
	}
	return f
}

// Add increases a counter (or gauge) by v.
func (r *Registry) Add(name string, v float64, kv ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fam(name).values[labels(kv)] += v
}

func (r *Registry) Inc(name string, kv ...string) { r.Add(name, 1, kv...) }

// Set sets a gauge.
func (r *Registry) Set(name string, v float64, kv ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fam(name).values[labels(kv)] = v
}

// Reset clears a gauge family (before re-setting a full snapshot).
func (r *Registry) Reset(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fam(name).values = map[string]float64{}
}

// Observe records one observation in a summary (_sum and _count).
func (r *Registry) Observe(name string, v float64, kv ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.fam(name)
	l := labels(kv)
	f.values["_sum"+l] += v
	f.values["_count"+l]++
}

// WriteText writes all metrics in the Prometheus text format.
func (r *Registry) WriteText(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.fams))
	for n := range r.fams {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := r.fams[n]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", n, f.help, n, f.kind)
		keys := make([]string, 0, len(f.values))
		for k := range f.values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := strconv.FormatFloat(f.values[k], 'g', -1, 64)
			if f.kind == Summary {
				suffix, l := "_sum", strings.TrimPrefix(k, "_sum")
				if strings.HasPrefix(k, "_count") {
					suffix, l = "_count", strings.TrimPrefix(k, "_count")
				}
				fmt.Fprintf(w, "%s%s%s %s\n", n, suffix, l, v)
				continue
			}
			fmt.Fprintf(w, "%s%s %s\n", n, k, v)
		}
	}
}

func (r *Registry) Text() string {
	var b strings.Builder
	r.WriteText(&b)
	return b.String()
}

// Handler serves metrics: before runs first (to refresh gauges), then
// render writes the body.
func Handler(before func(), render func(io.Writer)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if before != nil {
			before()
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		render(w)
	})
}

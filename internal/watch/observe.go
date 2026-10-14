package watch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kuramichi2010/nethergate/internal/audit"
	"github.com/kuramichi2010/nethergate/internal/enforce"
	"github.com/kuramichi2010/nethergate/internal/forward"
	"github.com/kuramichi2010/nethergate/internal/metrics"
	"github.com/kuramichi2010/nethergate/internal/playbook"
)

func (d *Daemon) auditFiles() []string {
	return []string{
		filepath.Join(d.Cfg.StateDir, "watch-audit.jsonl"),
		filepath.Join(d.Cfg.StateDir, "mcp-audit.jsonl"),
		filepath.Join(d.Cfg.StateDir, "playbook-audit.jsonl"),
		filepath.Join(d.Cfg.EnforcerStateDir, "enforcer-audit.jsonl"),
	}
}

func newMetrics() *metrics.Registry {
	m := metrics.New()
	m.Describe("nethergate_incidents", metrics.Gauge, "Sources active in the last 10 minutes, by severity.")
	m.Describe("nethergate_auto_block_requests_total", metrics.Counter, "Automatic block requests sent to the enforcer, by kind (rules|playbook) and result (ok|refused).")
	m.Describe("nethergate_triage_runs_total", metrics.Counter, "AI triage runs, by result (ok|error).")
	m.Describe("nethergate_triage_duration_seconds", metrics.Summary, "Duration of AI triage runs.")
	m.Describe("nethergate_notifications_total", metrics.Counter, "Webhook notifications, by result (sent|error|dropped).")
	m.Describe("nethergate_log_tail_lag_bytes", metrics.Gauge, "Bytes appended to a log that have not been analysed yet.")
	m.Describe("nethergate_reviews_pending", metrics.Gauge, "Cases the AI asked a human to decide.")
	m.Describe("nethergate_playbook_proposals_pending", metrics.Gauge, "AI-proposed rules waiting for approval.")
	m.Describe("nethergate_playbook_rules", metrics.Gauge, "Approved playbook rules, by verdict.")
	m.Describe("nethergate_audit_records", metrics.Gauge, "Records in each audit chain.")
	m.Describe("nethergate_forward_events_total", metrics.Counter, "Audit records delivered to the SIEM, by file.")
	m.Describe("nethergate_forward_lag_bytes", metrics.Gauge, "Audit bytes not yet delivered to the SIEM, by file.")
	m.Describe("nethergate_forward_errors_total", metrics.Counter, "Failed deliveries to the SIEM (retried with backoff).")
	m.Describe("nethergate_forward_tamper_events_total", metrics.Counter, "Audit files that shrank, were replaced or disappeared.")
	m.Describe("nethergate_enforcer_up", metrics.Gauge, "1 if the enforcer answered the last metrics scrape.")
	return m
}

// inc / observe are no-ops when the daemon was built without metrics (tests).
func (d *Daemon) inc(name string, kv ...string) {
	if d.metrics != nil {
		d.metrics.Inc(name, kv...)
	}
}

func (d *Daemon) observe(name string, v float64, kv ...string) {
	if d.metrics != nil {
		d.metrics.Observe(name, v, kv...)
	}
}

// refreshGauges recomputes the values that are cheap to read at scrape time.
func (d *Daemon) refreshGauges() {
	m := d.metrics
	reviews, _ := playbook.LoadList[playbook.Review](d.Cfg.ReviewsPath())
	m.Set("nethergate_reviews_pending", float64(len(reviews)))
	proposals, _ := playbook.Load(d.Cfg.ProposalsPath())
	m.Set("nethergate_playbook_proposals_pending", float64(len(proposals)))
	rules, _ := playbook.Load(d.Cfg.Playbook.Path)
	counts := map[string]float64{playbook.Malicious: 0, playbook.Allow: 0}
	for _, r := range rules {
		counts[r.Verdict]++
	}
	for v, n := range counts {
		m.Set("nethergate_playbook_rules", n, "verdict", v)
	}
	for _, f := range d.auditFiles() {
		if n, _, err := audit.HeadOf(f); err == nil {
			m.Set("nethergate_audit_records", float64(n), "file", filepath.Base(f))
		}
	}
	if d.forwarder != nil {
		st := d.forwarder.Stats()
		for f, n := range st.Sent {
			m.Set("nethergate_forward_events_total", float64(n), "file", f)
		}
		for f, n := range st.LagBytes {
			m.Set("nethergate_forward_lag_bytes", float64(n), "file", f)
		}
		m.Set("nethergate_forward_errors_total", float64(st.Errors))
		m.Set("nethergate_forward_tamper_events_total", float64(st.Tampers))
	}
}

// render writes our metrics followed by the enforcer's, scraped over its
// socket (the enforcer has no network access of its own).
func (d *Daemon) render(w io.Writer) {
	resp, err := enforce.Call(d.Cfg.EnforcerSocket, enforce.Request{Op: "metrics"})
	up := 0.0
	if err == nil && resp.OK {
		up = 1
	}
	d.metrics.Set("nethergate_enforcer_up", up)
	d.metrics.WriteText(w)
	if up == 1 {
		io.WriteString(w, resp.Metrics)
	}
}

// updateStepGauges records per-step values (called from step).
func (d *Daemon) updateStepGauges(now time.Time) {
	if d.metrics == nil {
		return
	}
	bands := map[string]float64{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, inc := range d.analyzer.Incidents(now.Add(-10*time.Minute), 1) {
		switch {
		case inc.Score >= 80:
			bands["critical"]++
		case inc.Score >= 50:
			bands["high"]++
		case inc.Score >= 25:
			bands["medium"]++
		default:
			bands["low"]++
		}
	}
	for b, n := range bands {
		d.metrics.Set("nethergate_incidents", n, "severity", b)
	}
	for _, t := range d.tailers {
		if st, err := os.Stat(t.src.Path); err == nil && t.f != nil {
			d.metrics.Set("nethergate_log_tail_lag_bytes", float64(max(0, st.Size()-t.offset)), "file", filepath.Base(t.src.Path))
		}
	}
}

// startObservability launches SIEM forwarding and the metrics endpoint.
func (d *Daemon) startObservability(ctx context.Context) error {
	var sinks []forward.Sink
	if f := d.Cfg.Forward.Syslog; f != nil {
		s, err := forward.NewSyslogSink(f.Address, f.CAFile, f.ServerName, f.Plaintext)
		if err != nil {
			return fmt.Errorf("forward.syslog: %w", err)
		}
		sinks = append(sinks, s)
	}
	if f := d.Cfg.Forward.HTTP; f != nil {
		s, err := forward.NewHTTPSink(f.URL, f.Format, f.TokenEnv)
		if err != nil {
			return fmt.Errorf("forward.http: %w", err)
		}
		sinks = append(sinks, s)
	}
	if len(sinks) > 0 {
		host, _ := os.Hostname()
		d.forwarder = &forward.Forwarder{Files: d.auditFiles(), Sinks: sinks, Host: host,
			StatePath: filepath.Join(d.Cfg.StateDir, "forward-state.json")}
		go d.forwarder.Run(d.Cfg.Forward.Interval.D(), ctx.Done())
		log.Printf("forwarding audit records to %d sink(s)", len(sinks))
	}
	if addr := d.Cfg.Metrics.Listen; addr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.Handler(d.refreshGauges, d.render))
		srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
		go func() {
			<-ctx.Done()
			_ = srv.Close()
		}()
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics: %v", err)
			}
		}()
		log.Printf("metrics on http://%s/metrics", addr)
	}
	return nil
}

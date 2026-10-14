package forward

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// SyslogSink sends RFC 5424 messages over TCP with octet-counting framing
// (RFC 6587), normally inside TLS (RFC 5425, port 6514).
type SyslogSink struct {
	Address string
	TLS     *tls.Config // nil = plaintext TCP (only for a local relay)
	Dial    func(network, addr string) (net.Conn, error)

	mu   sync.Mutex
	conn net.Conn
}

// NewSyslogSink builds a TLS syslog sink. caFile may be empty to use the
// system roots; plaintext must be requested explicitly.
func NewSyslogSink(address, caFile, serverName string, plaintext bool) (*SyslogSink, error) {
	s := &SyslogSink{Address: address}
	if plaintext {
		return s, nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates", caFile)
		}
		cfg.RootCAs = pool
	}
	s.TLS = cfg
	return s, nil
}

func (s *SyslogSink) Name() string { return "syslog " + s.Address }

func (s *SyslogSink) connect() (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if s.Dial != nil {
		return s.Dial("tcp", s.Address)
	}
	if s.TLS != nil {
		return tls.DialWithDialer(d, "tcp", s.Address, s.TLS)
	}
	return d.Dial("tcp", s.Address)
}

// Format renders one event as an RFC 5424 message: facility authpriv (10),
// severity notice (5) for audit/anchor, alert (1) for tamper.
func Format(ev Event) []byte {
	sev := 5
	if ev.Type == "tamper" {
		sev = 1
	}
	host := ev.Host
	if host == "" {
		host = "-"
	}
	body, _ := json.Marshal(ev)
	msg := fmt.Sprintf("<%d>1 %s %s nethergate - %s - %s", 10*8+sev, ev.Time.UTC().Format(time.RFC3339Nano), host, ev.Type, body)
	return []byte(fmt.Sprintf("%d %s", len(msg), msg))
}

func (s *SyslogSink) Send(events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		c, err := s.connect()
		if err != nil {
			return err
		}
		s.conn = c
	}
	var buf bytes.Buffer
	for _, ev := range events {
		buf.Write(Format(ev))
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err := s.conn.Write(buf.Bytes()); err != nil {
		s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// HTTPSink POSTs newline-delimited JSON. Format "ndjson" (Elastic ingest,
// Loki/Vector/Fluent Bit HTTP inputs, custom collectors) or "splunk_hec".
type HTTPSink struct {
	URL    string
	Format string
	Token  string
	Client *http.Client
}

func NewHTTPSink(rawURL, format, tokenEnv string) (*HTTPSink, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("forward.http.url must be an https:// URL")
	}
	if format == "" {
		format = "ndjson"
	}
	if format != "ndjson" && format != "splunk_hec" {
		return nil, fmt.Errorf("forward.http.format must be ndjson or splunk_hec, not %q", format)
	}
	s := &HTTPSink{URL: rawURL, Format: format, Client: &http.Client{Timeout: 15 * time.Second}}
	if tokenEnv != "" {
		s.Token = os.Getenv(tokenEnv)
		if s.Token == "" {
			return nil, fmt.Errorf("environment variable %s (forward.http.token_env) is empty", tokenEnv)
		}
	}
	return s, nil
}

func (s *HTTPSink) Name() string {
	u, _ := url.Parse(s.URL)
	return "http " + u.Host // never log the path/query: it may carry a token
}

func (s *HTTPSink) Send(events []Event) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		var v any = ev
		if s.Format == "splunk_hec" {
			v = map[string]any{"time": float64(ev.Time.UnixNano()) / 1e9, "host": ev.Host,
				"source": ev.File, "sourcetype": "nethergate:" + ev.Type, "event": ev}
		}
		if err := enc.Encode(v); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(http.MethodPost, s.URL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.Token != "" {
		if s.Format == "splunk_hec" {
			req.Header.Set("Authorization", "Splunk "+s.Token)
		} else {
			req.Header.Set("Authorization", "Bearer "+s.Token)
		}
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL may contain a token
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

package logscan

import (
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/kuramichi2010/nethergate/internal/config"
	"github.com/kuramichi2010/nethergate/internal/detect"
)

func benchCfg(b *testing.B) *config.Config {
	p := os.Getenv("NG_BENCH_LOG")
	if p == "" {
		b.Skip("set NG_BENCH_LOG")
	}
	c := config.Default()
	c.Logs = []config.LogSource{{Path: p, Format: "nginx"}}
	return c
}

func BenchmarkScan(b *testing.B) {
	c := benchCfg(b)
	for i := 0; i < b.N; i++ {
		if _, err := Scan(c, nil, time.Now()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanIP(b *testing.B) {
	c := benchCfg(b)
	ip := netip.MustParseAddr("203.0.113.7")
	for i := 0; i < b.N; i++ {
		if _, err := ScanIP(c, nil, ip, time.Now()); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkResident reports the live heap held by an analyzer after a full
// scan: what the watch daemon keeps in memory for the window.
func BenchmarkResident(b *testing.B) {
	c := benchCfg(b)
	var keep *detect.Analyzer
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		a, err := Scan(c, nil, time.Now())
		if err != nil {
			b.Fatal(err)
		}
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), "MB-live")
		keep = a
	}
	runtime.KeepAlive(keep)
}

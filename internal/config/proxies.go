package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// Presets usable in trusted_proxies. Cloudflare publishes its ranges at
// https://www.cloudflare.com/ips/ ; `nethergate proxies cloudflare` prints
// the live list so this copy can be checked (last synced 2026-10).
var proxyPresets = map[string][]string{
	"cloudflare": {
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
		"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	},
}

// PresetProxies returns a copy of a preset's ranges.
func PresetProxies(name string) []string {
	return append([]string(nil), proxyPresets[name]...)
}

func parseProxies(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, e := range entries {
		if list, ok := proxyPresets[strings.ToLower(e)]; ok {
			for _, s := range list {
				out = append(out, netip.MustParsePrefix(s))
			}
			continue
		}
		p, err := netip.ParsePrefix(e)
		if err != nil {
			a, err2 := netip.ParseAddr(e)
			if err2 != nil || a.Zone() != "" {
				return nil, fmt.Errorf("trusted_proxies entry %q: not a CIDR, address or preset (cloudflare)", e)
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

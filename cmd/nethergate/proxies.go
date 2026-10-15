package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/kuramichi2010/nethergate/internal/config"
)

// runProxies compares the built-in Cloudflare ranges with the live list,
// so the preset can be kept current (exit status 1 if they differ).
func runProxies(args []string) error {
	if len(args) != 1 || args[0] != "cloudflare" {
		return errors.New("usage: nethergate proxies cloudflare")
	}
	c := &http.Client{Timeout: 15 * time.Second}
	var live []string
	for _, u := range []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"} {
		resp, err := c.Get(u)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
		for sc.Scan() {
			if p, err := netip.ParsePrefix(sc.Text()); err == nil {
				live = append(live, p.Masked().String())
			}
		}
		resp.Body.Close()
	}
	if len(live) == 0 {
		return errors.New("no ranges fetched")
	}
	builtin := config.PresetProxies("cloudflare")
	diff := false
	for _, p := range live {
		if !slices.Contains(builtin, p) {
			fmt.Println("+ missing from the built-in list:", p)
			diff = true
		}
	}
	for _, p := range builtin {
		if !slices.Contains(live, p) {
			fmt.Println("- no longer published by Cloudflare:", p)
			diff = true
		}
	}
	if diff {
		return errors.New("built-in Cloudflare ranges are out of date: list the current ones in trusted_proxies explicitly")
	}
	fmt.Printf("built-in Cloudflare ranges are current (%d prefixes)\n", len(live))
	return nil
}

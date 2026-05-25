package scanner

import (
	"github.com/hsxa-ai/net-probe/internal/banner"
	"github.com/hsxa-ai/net-probe/internal/config"
	"github.com/hsxa-ai/net-probe/internal/mdns"
	"github.com/hsxa-ai/net-probe/internal/result"
)

// task represents a single (IP, port) scan unit.
type task struct {
	ip   string
	port uint16
}

// runTask executes the full probe pipeline for one IP:Port combination:
//  1. If port == 5353, run mDNS unicast probe directly (UDP).
//  2. Otherwise, TCP-probe the port; if open, also run mDNS on port 5353 for
//     the same host to correlate service info.
func runTask(t task, cfg *config.ScanConfig) *result.HostResult {
	if t.port == 5353 {
		// mDNS port: run DNS-SD probe
		hr := mdns.Probe(t.ip, t.port, cfg.Timeout)
		banner.Assemble(hr)
		return hr
	}

	// TCP probe
	open := tcpProbe(t.ip, t.port, cfg.Timeout)
	hr := &result.HostResult{
		IP:    t.ip,
		Port:  t.port,
		Proto: "tcp",
		Open:  open,
	}

	if open {
		// Enrich with mDNS service info from port 5353 on the same host.
		mdnsHR := mdns.Probe(t.ip, 5353, cfg.Timeout)
		if mdnsHR != nil {
			hr.Services = mdnsHR.Services
			hr.DeviceInfo = mdnsHR.DeviceInfo
			hr.PTRAnswers = mdnsHR.PTRAnswers
		}
		banner.Assemble(hr)
	}

	return hr
}

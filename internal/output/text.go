package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hsxa-ai/net-probe/internal/result"
)

// TextWriter formats ScanResult as human-readable text.
type TextWriter struct{}

// Write outputs the scan result in the documented text format.
func (tw *TextWriter) Write(w io.Writer, sr *result.ScanResult) error {
	// Group results by IP address so all ports for the same host are together.
	ipOrder, byIP := groupByIP(sr.Hosts)

	for _, ip := range ipOrder {
		hosts := byIP[ip]
		// Print IP header once per host.
		fmt.Fprintf(w, "[%s]\n", ip)

		// Collect all open services across ports for this IP.
		var allServices []result.ServiceRecord
		var deviceInfo *result.DeviceInfo
		var ptrAnswers []string

		for _, hr := range hosts {
			if !hr.Open {
				continue
			}
			allServices = append(allServices, hr.Services...)
			if hr.DeviceInfo != nil && deviceInfo == nil {
				deviceInfo = hr.DeviceInfo
			}
			ptrAnswers = mergeStrings(ptrAnswers, hr.PTRAnswers)
		}

		// services: section
		if len(allServices) > 0 {
			fmt.Fprintln(w, "services:")
			for _, svc := range allServices {
				printService(w, svc)
			}
		}

		// device-info: section
		if deviceInfo != nil {
			fmt.Fprintln(w, "device-info:")
			if deviceInfo.Name != "" {
				fmt.Fprintf(w, "  Name=%s\n", deviceInfo.Name)
			}
			for k, v := range deviceInfo.Fields {
				fmt.Fprintf(w, "  %s=%s\n", k, v)
			}
		}

		// answers: section
		if len(ptrAnswers) > 0 {
			fmt.Fprintln(w, "answers:")
			fmt.Fprintln(w, "  PTR:")
			for _, ans := range ptrAnswers {
				fmt.Fprintf(w, "    %s\n", ans)
			}
		}

		fmt.Fprintln(w) // blank line between hosts
	}

	// Summary line goes to stderr so it never pollutes stdout pipelines.
	fmt.Fprintf(os.Stderr, "Scanned %d target(s), %d open, elapsed %s\n",
		sr.Total, sr.OpenCount, sr.Elapsed)
	return nil
}

// printService writes a single service block.
func printService(w io.Writer, svc result.ServiceRecord) {
	// Header: port/proto shortname:
	shortName := shortSvcType(svc.ServiceType)
	fmt.Fprintf(w, "  %d/tcp %s:\n", svc.Port, shortName)

	// Instance name (first label is the "friendly" name)
	name := svc.InstanceName
	if idx := strings.Index(name, "."); idx >= 0 {
		name = name[:idx]
	}
	if name != "" {
		fmt.Fprintf(w, "    Name=%s\n", name)
	}

	if svc.IPv4 != nil {
		fmt.Fprintf(w, "    IPv4=%s\n", svc.IPv4.String())
	}
	if svc.IPv6 != nil {
		fmt.Fprintf(w, "    IPv6=%s\n", svc.IPv6.String())
	}
	if svc.Hostname != "" {
		fmt.Fprintf(w, "    Hostname=%s\n", svc.Hostname)
	}
	if svc.TTL > 0 {
		fmt.Fprintf(w, "    TTL=%d\n", svc.TTL)
	}

	// TXT records (already normalized by banner.Assemble)
	if len(svc.TXTRecords) > 0 {
		fmt.Fprintf(w, "    %s\n", strings.Join(svc.TXTRecords, ","))
	}
}

// shortSvcType strips leading underscore and everything from the second label.
// "_workstation._tcp.local" -> "workstation"
func shortSvcType(svcType string) string {
	s := strings.TrimPrefix(svcType, "_")
	if idx := strings.Index(s, "."); idx >= 0 {
		s = s[:idx]
	}
	return s
}

// groupByIP returns an ordered slice of IPs and a map from IP to HostResults.
func groupByIP(hosts []*result.HostResult) ([]string, map[string][]*result.HostResult) {
	order := make([]string, 0)
	seen := make(map[string]struct{})
	byIP := make(map[string][]*result.HostResult)

	for _, hr := range hosts {
		if _, ok := seen[hr.IP]; !ok {
			seen[hr.IP] = struct{}{}
			order = append(order, hr.IP)
		}
		byIP[hr.IP] = append(byIP[hr.IP], hr)
	}
	return order, byIP
}

// mergeStrings appends elements of b to a skipping duplicates.
func mergeStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a))
	for _, s := range a {
		seen[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			a = append(a, s)
		}
	}
	return a
}

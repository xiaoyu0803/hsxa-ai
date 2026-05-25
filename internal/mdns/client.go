package mdns

import (
	"strings"
	"time"

	"github.com/hsxa-ai/net-probe/internal/result"
)

// Probe performs a full mDNS/DNS-SD interrogation of targetIP and returns a
// populated HostResult. The host is considered "open" (mDNS-responsive) if at
// least one PTR record is received.
func Probe(targetIP string, port uint16, timeout time.Duration) *result.HostResult {
	hr := &result.HostResult{
		IP:    targetIP,
		Port:  port,
		Proto: "udp",
	}

	if timeout <= 0 {
		timeout = queryTimeout
	}

	targetPort := int(port)
	if targetPort == 0 {
		targetPort = mDNSPort
	}

	// shortTimeout is used for queries to well-known service types that the
	// host may not support. We don't want each miss to burn the full timeout.
	// Cap at 1 second so that 18 non-responding types add at most ~18s overhead.
	shortTimeout := timeout / 5
	if shortTimeout < 300*time.Millisecond {
		shortTimeout = 300 * time.Millisecond
	}
	if shortTimeout > time.Second {
		shortTimeout = time.Second
	}

	// Step 1: Discover service types via _services._dns-sd._udp.local.
	discoveryReplies, _ := sendQuery(targetIP, targetPort, buildPTRQuery(discoveryName), timeout)
	discoveredTypes := extractPTRTargets(discoveryReplies)

	// Collect raw PTR answers from discovery for the output "answers" section.
	// Normalize: strip trailing dots so dedup works correctly.
	var rawPTRAnswers []string
	for _, name := range discoveredTypes {
		rawPTRAnswers = appendUnique(rawPTRAnswers, stripTrailingDot(name))
	}

	// Build the service type list: start with discovered types, then add
	// well-known types not already included.
	serviceTypes := mergeUnique(discoveredTypes, knownServiceTypes)

	// Step 2 & 3: For each service type, find instances then query SRV+TXT+A/AAAA.
	var services []result.ServiceRecord
	var deviceInfo *result.DeviceInfo

	for _, svcType := range serviceTypes {
		// Use the shorter timeout for types not surfaced by discovery.
		qt := shortTimeout
		for _, d := range discoveredTypes {
			if d == svcType {
				qt = timeout
				break
			}
		}

		ptrReplies, err := sendQuery(targetIP, targetPort, buildPTRQuery(svcType), qt)
		if err != nil || len(ptrReplies) == 0 {
			continue
		}
		instances := extractPTRTargets(ptrReplies)
		if len(instances) == 0 {
			continue
		}

		// We received a response for this service type – mark host as open.
		hr.Open = true

		// Accumulate active service types into PTR answers (normalized, no trailing dot).
		rawPTRAnswers = appendUnique(rawPTRAnswers, stripTrailingDot(svcType))

		for _, instanceName := range instances {
			// Step 4: SRV + TXT for the instance.
			srvTxtReplies, _ := sendQuery(targetIP, targetPort, buildSRVTXTQuery(instanceName), timeout)
			srv := extractSRV(srvTxtReplies)
			txtStrings := extractTXT(srvTxtReplies)

			var svcPort uint16
			var hostname string
			var ttl uint32

			if srv != nil {
				svcPort = srv.Port
				hostname = srv.Target
				ttl = srv.Hdr.Ttl
			}

			// Step 5: A and AAAA for the hostname.
			var ipv4, ipv6 []byte
			if hostname != "" {
				aReplies, _ := sendQuery(targetIP, targetPort, buildAQuery(hostname), timeout)
				ipv4 = extractA(aReplies)

				aaaaReplies, _ := sendQuery(targetIP, targetPort, buildAAAAQuery(hostname), timeout)
				ipv6 = extractAAAA(aaaaReplies)
			}

			svcType2 := serviceTypeFromInstance(instanceName)

			sr := result.ServiceRecord{
				ServiceType:  stripTrailingDot(svcType2),
				InstanceName: stripTrailingDot(instanceName),
				Hostname:     stripTrailingDot(hostname),
				Port:         svcPort,
				IPv4:         ipv4,
				IPv6:         ipv6,
				TXTRecords:   txtStrings,
				TTL:          ttl,
			}
			services = append(services, sr)

			// Parse _device-info._tcp records.
			if strings.Contains(svcType, "_device-info._tcp") {
				deviceInfo = parseDeviceInfo(instanceName, txtStrings)
			}
		}
	}

	hr.Services = services
	hr.DeviceInfo = deviceInfo
	hr.PTRAnswers = rawPTRAnswers

	return hr
}

// appendUnique appends s to slice only if not already present.
func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

// parseDeviceInfo builds a DeviceInfo from TXT records of _device-info._tcp.
func parseDeviceInfo(instanceName string, txtRecords []string) *result.DeviceInfo {
	di := &result.DeviceInfo{
		Fields: make(map[string]string),
	}
	// Extract name from instance (first label before first dot).
	name := instanceName
	if idx := strings.Index(name, "."); idx >= 0 {
		name = name[:idx]
	}
	di.Name = name

	for _, txt := range txtRecords {
		if eqIdx := strings.Index(txt, "="); eqIdx >= 0 {
			k := strings.TrimSpace(txt[:eqIdx])
			v := strings.TrimSpace(txt[eqIdx+1:])
			if k != "" {
				di.Fields[k] = v
			}
		}
	}
	return di
}

// mergeUnique appends elements of b to a, skipping duplicates (case-sensitive).
func mergeUnique(a, b []string) []string {
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

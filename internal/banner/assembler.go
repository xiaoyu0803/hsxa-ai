package banner

import (
	"fmt"
	"strings"

	"github.com/hsxa-ai/net-probe/internal/result"
)

// Assemble enriches a HostResult with human-readable banner fields derived
// from the mDNS ServiceRecords. It processes TXT records for each service and
// populates a DeviceInfo if one has not already been set by the mDNS client.
func Assemble(hr *result.HostResult) {
	if hr == nil {
		return
	}

	// If we don't yet have a DeviceInfo, try to build one from the services.
	if hr.DeviceInfo == nil {
		hr.DeviceInfo = buildDeviceInfoFromServices(hr.Services)
	}

	// Normalize TXT records: split comma-joined key=value strings.
	for i := range hr.Services {
		hr.Services[i].TXTRecords = normalizeTXT(hr.Services[i].TXTRecords)
	}
}

// buildDeviceInfoFromServices attempts to derive DeviceInfo from _device-info
// or other suitable service records.
func buildDeviceInfoFromServices(services []result.ServiceRecord) *result.DeviceInfo {
	for _, svc := range services {
		if strings.Contains(svc.ServiceType, "_device-info") {
			di := &result.DeviceInfo{
				Name:   extractName(svc.InstanceName),
				Fields: parseTXTMap(svc.TXTRecords),
			}
			return di
		}
	}
	return nil
}

// extractName returns the first label of a DNS instance name.
func extractName(instanceName string) string {
	if idx := strings.Index(instanceName, "."); idx >= 0 {
		return instanceName[:idx]
	}
	return instanceName
}

// parseTXTMap converts a list of TXT strings (key=value or k=v,k=v) into a map.
func parseTXTMap(txts []string) map[string]string {
	m := make(map[string]string)
	for _, txt := range txts {
		for _, kv := range strings.Split(txt, ",") {
			if eqIdx := strings.Index(kv, "="); eqIdx >= 0 {
				k := strings.TrimSpace(kv[:eqIdx])
				v := strings.TrimSpace(kv[eqIdx+1:])
				if k != "" {
					m[k] = v
				}
			}
		}
	}
	return m
}

// normalizeTXT expands any comma-separated key=value strings in a TXT record
// slice into individual entries, deduplicating as it goes.
func normalizeTXT(txts []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, txt := range txts {
		for _, kv := range splitTXT(txt) {
			kv = strings.TrimSpace(kv)
			if kv == "" {
				continue
			}
			if _, ok := seen[kv]; !ok {
				seen[kv] = struct{}{}
				out = append(out, kv)
			}
		}
	}
	return out
}

// splitTXT splits a TXT record string on commas only when the comma is between
// key=value pairs. A naive split on comma is used here; this handles the
// common mDNS TXT format used by e.g. QNAP devices.
func splitTXT(txt string) []string {
	// If the string contains '=' it is likely a key=value sequence.
	if strings.Contains(txt, "=") {
		return strings.Split(txt, ",")
	}
	return []string{txt}
}

// FormatServiceLine returns a one-line summary of a ServiceRecord for display.
func FormatServiceLine(sr result.ServiceRecord) string {
	return fmt.Sprintf("%d/%s %s", sr.Port, "tcp", shortServiceType(sr.ServiceType))
}

// shortServiceType extracts the service label from e.g. "_workstation._tcp.local".
func shortServiceType(svcType string) string {
	// _workstation._tcp.local -> workstation
	s := strings.TrimPrefix(svcType, "_")
	if idx := strings.Index(s, "."); idx >= 0 {
		s = s[:idx]
	}
	return s
}

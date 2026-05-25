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

	// Normalize TXT records: deduplicate entries.
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

// parseTXTMap converts a list of TXT strings (each "key=value") into a map.
// Values may contain commas; only the first '=' is treated as a separator.
func parseTXTMap(txts []string) map[string]string {
	m := make(map[string]string)
	for _, txt := range txts {
		if eqIdx := strings.Index(txt, "="); eqIdx >= 0 {
			k := strings.TrimSpace(txt[:eqIdx])
			v := strings.TrimSpace(txt[eqIdx+1:])
			if k != "" {
				m[k] = v
			}
		}
	}
	return m
}

// normalizeTXT deduplicates TXT record strings. Each string in txts should
// already be a single key=value entry as delivered by the DNS protocol – we
// do NOT split on commas because values themselves may legally contain commas
// (e.g. "features=0x4A7FCFD5,0x38174FDE" or "cn=0,1,2,3").
func normalizeTXT(txts []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if txt == "" {
			continue
		}
		if _, ok := seen[txt]; !ok {
			seen[txt] = struct{}{}
			out = append(out, txt)
		}
	}
	return out
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

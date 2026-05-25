package mdns

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// extractPTRTargets returns all PTR rdata strings from a list of messages.
func extractPTRTargets(msgs []*dns.Msg) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, m := range msgs {
		for _, rr := range allRecords(m) {
			if ptr, ok := rr.(*dns.PTR); ok {
				name := ptr.Ptr
				if _, dup := seen[name]; !dup {
					seen[name] = struct{}{}
					out = append(out, name)
				}
			}
		}
	}
	return out
}

// extractSRV returns the first SRV record found across the messages.
func extractSRV(msgs []*dns.Msg) *dns.SRV {
	for _, m := range msgs {
		for _, rr := range allRecords(m) {
			if srv, ok := rr.(*dns.SRV); ok {
				return srv
			}
		}
	}
	return nil
}

// extractTXT returns all TXT strings found across the messages.
func extractTXT(msgs []*dns.Msg) []string {
	var out []string
	for _, m := range msgs {
		for _, rr := range allRecords(m) {
			if txt, ok := rr.(*dns.TXT); ok {
				out = append(out, txt.Txt...)
			}
		}
	}
	return out
}

// extractA returns the first IPv4 address found across the messages.
func extractA(msgs []*dns.Msg) net.IP {
	for _, m := range msgs {
		for _, rr := range allRecords(m) {
			if a, ok := rr.(*dns.A); ok {
				return a.A
			}
		}
	}
	return nil
}

// extractAAAA returns the first IPv6 address found across the messages.
func extractAAAA(msgs []*dns.Msg) net.IP {
	for _, m := range msgs {
		for _, rr := range allRecords(m) {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				return aaaa.AAAA
			}
		}
	}
	return nil
}

// allRecords aggregates Answer, Ns, and Extra sections of a DNS message.
func allRecords(m *dns.Msg) []dns.RR {
	if m == nil {
		return nil
	}
	var rrs []dns.RR
	rrs = append(rrs, m.Answer...)
	rrs = append(rrs, m.Ns...)
	rrs = append(rrs, m.Extra...)
	return rrs
}

// serviceTypeFromInstance derives the service type from an instance name.
// e.g. "MyDevice._workstation._tcp.local." -> "_workstation._tcp.local."
func serviceTypeFromInstance(instanceName string) string {
	// The instance name is <label>.<service>.<proto>.local.
	// We strip the first label.
	idx := strings.Index(instanceName, ".")
	if idx < 0 {
		return instanceName
	}
	return instanceName[idx+1:]
}

// stripTrailingDot removes the trailing dot from a DNS name.
func stripTrailingDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

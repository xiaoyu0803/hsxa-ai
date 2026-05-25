package output

import (
	"encoding/json"
	"io"

	"github.com/hsxa-ai/net-probe/internal/result"
)

// JSONWriter formats ScanResult as indented JSON.
type JSONWriter struct{}

// Write serialises the scan result to JSON.
func (jw *JSONWriter) Write(w io.Writer, sr *result.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonPayload(sr))
}

// jsonPayload converts a ScanResult into a JSON-friendly anonymous struct so
// that net.IP fields are rendered as strings.
func jsonPayload(sr *result.ScanResult) interface{} {
	type svcJSON struct {
		ServiceType  string   `json:"service_type"`
		InstanceName string   `json:"instance_name"`
		Hostname     string   `json:"hostname"`
		Port         uint16   `json:"port"`
		IPv4         string   `json:"ipv4,omitempty"`
		IPv6         string   `json:"ipv6,omitempty"`
		TXTRecords   []string `json:"txt_records,omitempty"`
		TTL          uint32   `json:"ttl"`
	}
	type devJSON struct {
		Name   string            `json:"name"`
		Fields map[string]string `json:"fields,omitempty"`
	}
	type hostJSON struct {
		IP         string    `json:"ip"`
		Port       uint16    `json:"port"`
		Proto      string    `json:"proto"`
		Open       bool      `json:"open"`
		Services   []svcJSON `json:"services,omitempty"`
		DeviceInfo *devJSON  `json:"device_info,omitempty"`
		PTRAnswers []string  `json:"ptr_answers,omitempty"`
	}
	type payload struct {
		Hosts     []hostJSON `json:"hosts"`
		Total     int        `json:"total"`
		OpenCount int        `json:"open_count"`
		Elapsed   string     `json:"elapsed"`
	}

	p := payload{
		Total:     sr.Total,
		OpenCount: sr.OpenCount,
		Elapsed:   sr.Elapsed,
	}
	for _, hr := range sr.Hosts {
		h := hostJSON{
			IP:         hr.IP,
			Port:       hr.Port,
			Proto:      hr.Proto,
			Open:       hr.Open,
			PTRAnswers: hr.PTRAnswers,
		}
		for _, svc := range hr.Services {
			s := svcJSON{
				ServiceType:  svc.ServiceType,
				InstanceName: svc.InstanceName,
				Hostname:     svc.Hostname,
				Port:         svc.Port,
				TXTRecords:   svc.TXTRecords,
				TTL:          svc.TTL,
			}
			if svc.IPv4 != nil {
				s.IPv4 = svc.IPv4.String()
			}
			if svc.IPv6 != nil {
				s.IPv6 = svc.IPv6.String()
			}
			h.Services = append(h.Services, s)
		}
		if hr.DeviceInfo != nil {
			h.DeviceInfo = &devJSON{
				Name:   hr.DeviceInfo.Name,
				Fields: hr.DeviceInfo.Fields,
			}
		}
		p.Hosts = append(p.Hosts, h)
	}
	return p
}

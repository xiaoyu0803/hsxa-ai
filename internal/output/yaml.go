package output

import (
	"io"

	"github.com/hsxa-ai/net-probe/internal/result"
	"gopkg.in/yaml.v3"
)

// YAMLWriter formats ScanResult as YAML.
type YAMLWriter struct{}

// Write serialises the scan result to YAML.
func (yw *YAMLWriter) Write(w io.Writer, sr *result.ScanResult) error {
	data := yamlPayload(sr)
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer enc.Close()
	return enc.Encode(data)
}

// yamlPayload converts a ScanResult into a YAML-friendly structure.
func yamlPayload(sr *result.ScanResult) interface{} {
	type svcYAML struct {
		ServiceType  string   `yaml:"service_type"`
		InstanceName string   `yaml:"instance_name"`
		Hostname     string   `yaml:"hostname,omitempty"`
		Port         uint16   `yaml:"port"`
		IPv4         string   `yaml:"ipv4,omitempty"`
		IPv6         string   `yaml:"ipv6,omitempty"`
		TXTRecords   []string `yaml:"txt_records,omitempty"`
		TTL          uint32   `yaml:"ttl"`
	}
	type devYAML struct {
		Name   string            `yaml:"name"`
		Fields map[string]string `yaml:"fields,omitempty"`
	}
	type hostYAML struct {
		IP         string    `yaml:"ip"`
		Port       uint16    `yaml:"port"`
		Proto      string    `yaml:"proto"`
		Open       bool      `yaml:"open"`
		Services   []svcYAML `yaml:"services,omitempty"`
		DeviceInfo *devYAML  `yaml:"device_info,omitempty"`
		PTRAnswers []string  `yaml:"ptr_answers,omitempty"`
	}
	type payload struct {
		Hosts     []hostYAML `yaml:"hosts"`
		Total     int        `yaml:"total"`
		OpenCount int        `yaml:"open_count"`
		Elapsed   string     `yaml:"elapsed"`
	}

	p := payload{
		Total:     sr.Total,
		OpenCount: sr.OpenCount,
		Elapsed:   sr.Elapsed,
	}
	for _, hr := range sr.Hosts {
		h := hostYAML{
			IP:         hr.IP,
			Port:       hr.Port,
			Proto:      hr.Proto,
			Open:       hr.Open,
			PTRAnswers: hr.PTRAnswers,
		}
		for _, svc := range hr.Services {
			s := svcYAML{
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
			h.DeviceInfo = &devYAML{
				Name:   hr.DeviceInfo.Name,
				Fields: hr.DeviceInfo.Fields,
			}
		}
		p.Hosts = append(p.Hosts, h)
	}
	return p
}

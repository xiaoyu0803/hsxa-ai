package result

import (
	"net"
)

// ServiceRecord holds a single mDNS/DNS-SD service record for a host.
type ServiceRecord struct {
	ServiceType  string
	InstanceName string
	Hostname     string
	Port         uint16
	IPv4         net.IP
	IPv6         net.IP
	TXTRecords   []string
	TTL          uint32
}

// DeviceInfo holds device-level metadata obtained from _device-info._tcp TXT.
type DeviceInfo struct {
	Name   string
	Fields map[string]string
}

// HostResult aggregates all scan findings for a single IP:Port target.
type HostResult struct {
	IP         string
	Port       uint16
	Proto      string
	Open       bool
	Services   []ServiceRecord
	DeviceInfo *DeviceInfo
	PTRAnswers []string
}

// ScanResult is the top-level structure returned by the scanner.
type ScanResult struct {
	Hosts     []*HostResult
	Total     int
	OpenCount int
	Elapsed   string
}

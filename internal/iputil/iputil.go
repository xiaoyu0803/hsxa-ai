package iputil

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Expand parses a comma-separated list of IP specifications and returns a flat
// slice of IP address strings. Each specification may be:
//   - A single IP:           192.168.1.1
//   - A CIDR block:          192.168.1.0/24
//   - A hyphen range:        192.168.1.1-192.168.1.50
//                            192.168.1.1-50  (short-form last-octet range)
func Expand(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ips, err := expandOne(part)
		if err != nil {
			return nil, err
		}
		out = append(out, ips...)
	}
	return out, nil
}

func expandOne(spec string) ([]string, error) {
	// CIDR
	if strings.Contains(spec, "/") {
		return expandCIDR(spec)
	}
	// Hyphen range
	if strings.Contains(spec, "-") {
		return expandRange(spec)
	}
	// Single IP
	if net.ParseIP(spec) == nil {
		return nil, fmt.Errorf("invalid IP address: %s", spec)
	}
	return []string{spec}, nil
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	var ips []string
	start := ip4ToUint32(ipNet.IP)
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	end := (start & mask) | ^mask

	for cur := start; cur <= end; cur++ {
		ips = append(ips, uint32ToIP4(cur).String())
	}
	return ips, nil
}

// expandRange handles both:
//
//	192.168.1.1-192.168.1.50  (two full IPs)
//	192.168.1.1-50            (last-octet shorthand)
func expandRange(spec string) ([]string, error) {
	dash := strings.LastIndex(spec, "-")
	left := spec[:dash]
	right := spec[dash+1:]

	startIP := net.ParseIP(left)
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP %q in range %q", left, spec)
	}
	startIP = startIP.To4()
	if startIP == nil {
		return nil, fmt.Errorf("only IPv4 ranges are supported: %q", spec)
	}

	var endIP net.IP
	if strings.Contains(right, ".") {
		// Full IP on the right side
		endIP = net.ParseIP(right)
		if endIP == nil {
			return nil, fmt.Errorf("invalid end IP %q in range %q", right, spec)
		}
		endIP = endIP.To4()
	} else {
		// Last-octet shorthand: copy first three octets from start
		var lastOctet int
		if _, err := fmt.Sscanf(right, "%d", &lastOctet); err != nil {
			return nil, fmt.Errorf("invalid range end %q in %q", right, spec)
		}
		endIP = make(net.IP, 4)
		copy(endIP, startIP)
		endIP[3] = byte(lastOctet)
	}

	start := ip4ToUint32(startIP)
	end := ip4ToUint32(endIP)
	if start > end {
		return nil, fmt.Errorf("start IP is greater than end IP in range %q", spec)
	}

	var ips []string
	for cur := start; cur <= end; cur++ {
		ips = append(ips, uint32ToIP4(cur).String())
	}
	return ips, nil
}

func ip4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

package portutil

import (
	"fmt"
	"strconv"
	"strings"
)

// Expand parses a comma-separated list of port specifications and returns a
// deduplicated, ordered slice of port numbers. Each specification may be:
//   - A single port:  80
//   - A range:        80-443
func Expand(raw string) ([]uint16, error) {
	seen := make(map[uint16]struct{})
	var out []uint16

	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ports, err := expandOne(part)
		if err != nil {
			return nil, err
		}
		for _, p := range ports {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func expandOne(spec string) ([]uint16, error) {
	if strings.Contains(spec, "-") {
		return expandRange(spec)
	}
	p, err := parsePort(spec)
	if err != nil {
		return nil, err
	}
	return []uint16{p}, nil
}

func expandRange(spec string) ([]uint16, error) {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range: %q", spec)
	}
	start, err := parsePort(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid start port in range %q: %w", spec, err)
	}
	end, err := parsePort(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid end port in range %q: %w", spec, err)
	}
	if start > end {
		return nil, fmt.Errorf("start port %d is greater than end port %d in %q", start, end, spec)
	}
	ports := make([]uint16, 0, int(end)-int(start)+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if n == 0 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range [1, 65535]", n)
	}
	return uint16(n), nil
}

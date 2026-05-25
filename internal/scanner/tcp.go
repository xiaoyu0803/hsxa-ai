package scanner

import (
	"fmt"
	"net"
	"time"
)

// tcpProbe attempts a TCP connection to host:port within timeout.
// Returns true if the connection succeeds (port is open).
func tcpProbe(host string, port uint16, timeout time.Duration) bool {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

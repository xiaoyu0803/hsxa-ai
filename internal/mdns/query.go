package mdns

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

// sendQuery dials a unicast UDP connection to targetIP:port, sends msg, and
// collects all reply messages until the deadline expires.
func sendQuery(targetIP string, port int, msg *dns.Msg, timeout time.Duration) ([]*dns.Msg, error) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(targetIP),
		Port: port,
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}

	var replies []*dns.Msg
	rbuf := make([]byte, 65535)
	for {
		n, err := conn.Read(rbuf)
		if err != nil {
			// deadline exceeded or connection closed – stop collecting
			break
		}
		reply := new(dns.Msg)
		if parseErr := reply.Unpack(rbuf[:n]); parseErr == nil {
			replies = append(replies, reply)
		}
		// After the first successful reply, shorten the deadline to 200ms to
		// catch any additional rapid responses (e.g., multiple mDNS answerers)
		// without blocking for the full timeout.
		if len(replies) == 1 {
			_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
		}
	}
	return replies, nil
}

// buildPTRQuery constructs a DNS PTR query for the given name.
func buildPTRQuery(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypePTR)
	msg.RecursionDesired = false
	return msg
}

// buildSRVTXTQuery constructs a combined SRV+TXT query for an instance name.
func buildSRVTXTQuery(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeANY)
	msg.RecursionDesired = false
	return msg
}

// buildAQuery constructs a DNS A query for the given hostname.
func buildAQuery(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.RecursionDesired = false
	return msg
}

// buildAAAAQuery constructs a DNS AAAA query for the given hostname.
func buildAAAAQuery(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeAAAA)
	msg.RecursionDesired = false
	return msg
}

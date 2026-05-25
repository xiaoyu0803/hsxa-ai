package mdns

import "time"

// knownServiceTypes is the set of DNS-SD service types we actively query for
// when a host does not enumerate its own services via _services._dns-sd.
var knownServiceTypes = []string{
	"_workstation._tcp.local.",
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_ftp._tcp.local.",
	"_ssh._tcp.local.",
	"_smb._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_nfs._tcp.local.",
	"_qdiscover._tcp.local.",
	"_device-info._tcp.local.",
	"_printer._tcp.local.",
	"_ipp._tcp.local.",
	"_ipps._tcp.local.",
	"_daap._tcp.local.",
	"_raop._tcp.local.",
	"_airplay._tcp.local.",
	"_homekit._tcp.local.",
	"_googlecast._tcp.local.",
	"_spotify-connect._tcp.local.",
}

// discoveryName is the PTR name used to discover all service types on a host.
const discoveryName = "_services._dns-sd._udp.local."

// mDNS multicast address and port (we use unicast to the target host).
const (
	mDNSPort = 5353
)

// queryTimeout is the per-query network deadline if not overridden by caller.
const queryTimeout = 3 * time.Second

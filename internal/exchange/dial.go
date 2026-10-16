package exchange

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// nonPublic are address ranges that are not on the public internet, beyond
// what netip.Addr's methods recognise.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // this network
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space (carrier-grade NAT)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and the broadcast address
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use IPv4/IPv6 translation
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001:10::/28"),    // deprecated ORCHID
	netip.MustParsePrefix("2001:20::/28"),    // ORCHIDv2
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
}

// IPv6 ranges that carry an IPv4 address, which is where packets to them
// end up: NAT64, 6to4 and the deprecated IPv4-compatible addresses.
var (
	nat64          = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
	ipv4Compatible = netip.MustParsePrefix("::/96")
)

// embeddedIPv4 returns the IPv4 address an IPv6 address carries, if any.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	b := ip.As16()
	switch {
	case ip.Is4In6():
		return ip.Unmap(), true
	case nat64.Contains(ip), ipv4Compatible.Contains(ip):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return ip, false
}

// publicAddress reports whether ip is an address on the public internet,
// judging an IPv6 address that carries an IPv4 address by the latter.
func publicAddress(ip netip.Addr) bool {
	if v4, ok := embeddedIPv4(ip); ok {
		ip = v4
	}
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// refusePrivate is a net.Dialer Control function. It sees the address
// actually being connected to, after name resolution, so a name that
// resolves to a private address, or starts to, is refused all the same.
func refusePrivate(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("refusing to connect to %s: not an IP address", address)
	}
	if !publicAddress(ip) {
		return fmt.Errorf("refusing to connect to %s: the issuer's settings refuse addresses that are not public", ip)
	}
	return nil
}

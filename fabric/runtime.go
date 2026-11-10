package fabric

import (
	"encoding/json"
	"strconv"
)

// Counter is an exact, possibly unbounded device integer such as a BGP
// message count. NX-OS counters can exceed int64, and the parser preserves
// them exactly; Int64 reports whether the value fits.
type Counter = json.Number

// CounterInt64 returns c as an int64 when it fits.
func CounterInt64(c Counter) (int64, bool) {
	n, err := strconv.ParseInt(string(c), 10, 64)
	return n, err == nil
}

// NVEPeer is one row of "show nve peers".
type NVEPeer struct {
	Interface string  `json:"interface"`
	PeerIP    string  `json:"peer_ip"`
	State     string  `json:"state"`
	LearnType string  `json:"learn_type"`
	Uptime    string  `json:"uptime"`
	RouterMAC *string `json:"router_mac"`
}

// NVEVNI is one row of "show nve vni".
type NVEVNI struct {
	Interface      string `json:"interface"`
	VNI            int    `json:"vni"`
	MulticastGroup string `json:"multicast_group"`
	State          string `json:"state"`
	Mode           string `json:"mode"`
	Type           string `json:"type"`
	Association    string `json:"association"`
	Flags          string `json:"flags"`
}

// BGPNeighbor is one neighbor of "show bgp l2vpn evpn summary".
type BGPNeighbor struct {
	VRF              string             `json:"vrf"`
	AddressFamily    string             `json:"address_family"`
	RouterID         string             `json:"router_id,omitempty"`
	LocalAS          string             `json:"local_as,omitempty"`
	TableVersion     *Counter           `json:"table_version,omitempty"`
	PeerIP           string             `json:"peer_ip"`
	Version          Counter            `json:"version"`
	RemoteAS         Counter            `json:"remote_as"`
	MessagesReceived Counter            `json:"messages_received"`
	MessagesSent     Counter            `json:"messages_sent"`
	InputQueue       Counter            `json:"input_queue"`
	OutputQueue      Counter            `json:"output_queue"`
	Uptime           string             `json:"uptime"`
	State            string             `json:"state"`
	PrefixesReceived *Counter           `json:"prefixes_received"`
	PrefixesByType   map[string]Counter `json:"prefixes_by_type,omitempty"` // type2, type3, type5, …
}

// OSPFNeighbor is one row of "show ip ospf neighbors".
type OSPFNeighbor struct {
	Process    string `json:"process,omitempty"`
	VRF        string `json:"vrf,omitempty"`
	NeighborID string `json:"neighbor_id"`
	Priority   int    `json:"priority"`
	State      string `json:"state"`
	Uptime     string `json:"uptime"`
	Address    string `json:"address"`
	Interface  string `json:"interface"`
}

// CDPNeighbor is one entry of "show cdp neighbors detail".
type CDPNeighbor struct {
	DeviceID            string             `json:"device_id"`
	NeighborName        string             `json:"neighbor_name"`
	Interface           string             `json:"interface"`
	NeighborInterface   string             `json:"neighbor_interface"`
	Platform            string             `json:"platform,omitempty"`
	Capabilities        string             `json:"capabilities,omitempty"`
	Holdtime            *Counter           `json:"holdtime,omitempty"`
	Version             string             `json:"version,omitempty"`
	InterfaceAddresses  []string           `json:"interface_addresses"`
	ManagementAddresses []string           `json:"management_addresses"`
	Attributes          map[string]*string `json:"attributes"`
}

// VPCPeerLink is a vPC peer-link row.
type VPCPeerLink struct {
	ID                   Counter `json:"id"`
	Interface            string  `json:"interface"`
	State                string  `json:"state"`
	ActiveVLANsSummary   string  `json:"active_vlans_summary"`
	ActiveVLANsTruncated bool    `json:"active_vlans_truncated"`
}

// VPCMember is a vPC member row.
type VPCMember struct {
	ID                    Counter `json:"id"`
	Interface             string  `json:"interface"`
	State                 string  `json:"state"`
	Consistency           string  `json:"consistency"`
	Reason                string  `json:"reason"`
	ActiveVLANsSummary    string  `json:"active_vlans_summary"`
	ActiveVLANsTruncated  bool    `json:"active_vlans_truncated"`
	ForwardingViaPeerLink *bool   `json:"forwarding_via_peer_link,omitempty"`
}

// VPC is "show vpc brief".
type VPC struct {
	DomainID          *int              `json:"domain_id,omitempty"`
	PeerStatus        string            `json:"peer_status,omitempty"`
	KeepaliveStatus   string            `json:"keepalive_status,omitempty"`
	ConsistencyStatus string            `json:"consistency_status,omitempty"`
	Role              string            `json:"role,omitempty"`
	Attributes        map[string]string `json:"attributes"`
	PeerLinks         []VPCPeerLink     `json:"peer_links"`
	Members           []VPCMember       `json:"members"`
}

// InterfaceStatus is one row of "show interface brief".
type InterfaceStatus struct {
	Interface     string `json:"interface"`
	Name          string `json:"name,omitempty"`
	Type          string `json:"type,omitempty"`
	VLAN          string `json:"vlan,omitempty"`
	SecondaryVLAN string `json:"secondary_vlan,omitempty"`
	Mode          string `json:"mode,omitempty"`
	State         string `json:"state"`
	Reason        string `json:"reason,omitempty"`
	Speed         string `json:"speed,omitempty"`
	Duplex        string `json:"duplex,omitempty"`
	PortChannel   string `json:"port_channel,omitempty"`
	VRF           string `json:"vrf,omitempty"`
	IPAddress     string `json:"ip_address,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	MTU           *int   `json:"mtu,omitempty"`
	Description   string `json:"description,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// PortChannelMember is one member of a port-channel.
type PortChannelMember struct {
	Interface string `json:"interface"`
	Flags     string `json:"flags"`
}

// PortChannel is one row of "show port-channel summary".
type PortChannel struct {
	Group     int                 `json:"group"`
	Interface string              `json:"interface"`
	Flags     string              `json:"flags"`
	Type      string              `json:"type"`
	Protocol  string              `json:"protocol"`
	Members   []PortChannelMember `json:"members"`
}

// MACEntry is one row of "show mac address-table".
type MACEntry struct {
	VLANID      *int   `json:"vlan_id"`
	MAC         string `json:"mac"`
	Type        string `json:"type"`
	Age         string `json:"age"`
	Secure      bool   `json:"secure"`
	Notify      bool   `json:"notify"`
	Destination string `json:"destination"`
	Flags       string `json:"flags,omitempty"`
}

// L2RouteNextHop is one next hop of an l2route entry.
type L2RouteNextHop struct {
	Address   string `json:"address,omitempty"`
	Interface string `json:"interface,omitempty"`
	IfIndex   *int   `json:"ifindex,omitempty"`
	Label     *int   `json:"label,omitempty"`
	Local     *bool  `json:"local,omitempty"`
}

// L2RouteMAC is one row of "show l2route evpn mac all".
type L2RouteMAC struct {
	TopologyID int              `json:"topology_id"`
	MAC        string           `json:"mac"`
	Producer   string           `json:"producer"`
	Flags      string           `json:"flags,omitempty"`
	Sequence   *int             `json:"sequence,omitempty"`
	NextHops   []L2RouteNextHop `json:"next_hops"`
}

// L2RouteMACIP is one row of "show l2route evpn mac-ip all".
type L2RouteMACIP struct {
	TopologyID int              `json:"topology_id"`
	MAC        string           `json:"mac"`
	HostIP     string           `json:"host_ip"`
	Producer   string           `json:"producer"`
	Flags      string           `json:"flags,omitempty"`
	Sequence   *int             `json:"sequence,omitempty"`
	NextHops   []L2RouteNextHop `json:"next_hops"`
}

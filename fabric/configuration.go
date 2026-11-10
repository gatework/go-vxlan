// Package fabric is the typed VXLAN/EVPN domain model: one device's parsed
// configuration and runtime state, and the fabric of devices that rules
// assess together.
//
// Field names and JSON tags match the NX-OS parser's output, so a parsed
// observation decodes into these types without loss; Decode rejects any
// field the model does not know, so unmodeled facts can never be silently
// dropped and treated as absent.
package fabric

// Configuration is one device's parsed running configuration.
type Configuration struct {
	Hostname            *string                     `json:"hostname"`
	Features            []string                    `json:"features"`
	DisabledFeatures    []string                    `json:"disabled_features"`
	NVOverlayEVPN       bool                        `json:"nv_overlay_evpn,omitempty"`
	AnycastMAC          string                      `json:"anycast_mac,omitempty"`
	Breakouts           map[string]Breakout         `json:"breakouts"`
	Interfaces          map[string]Interface        `json:"interfaces"`
	VLANVNIs            map[string]*int             `json:"vlan_vnis"`
	VRFs                map[string]VRF              `json:"vrfs"`
	NVE                 NVE                         `json:"nve"`
	EVPN                map[string]EVPNInstance     `json:"evpn"`
	BGP                 RoutingNode                 `json:"bgp"`
	OSPF                map[string]RoutingNode      `json:"ospf"`
	VPCDomain           *VPCDomain                  `json:"vpc_domain"`
	UnnumberedAddresses map[string][]string         `json:"unnumbered_addresses"`
	PrefixLists         map[string][]PrefixListRule `json:"prefix_lists"`
	IPv6PrefixLists     map[string][]PrefixListRule `json:"ipv6_prefix_lists"`
	RouteMaps           map[string][]RouteMapEntry  `json:"route_maps"`
	ACLs                map[string][]ACLEntry       `json:"acls"`
	AddressGroups       map[string][]string         `json:"address_groups"`
	StaticRoutes        []StaticRoute               `json:"static_routes"`
	Segments            []Segment                   `json:"segments"`
	ConfigDigest        string                      `json:"config_digest"`
	ReviewStatus        string                      `json:"review_status"`
	ReviewFindings      []RelationFinding           `json:"review_findings"`
	Operations          *Operations                 `json:"operations,omitempty"`
}

// Server is a management or relay server reference.
type Server struct {
	Address string `json:"address"`
	VRF     string `json:"vrf,omitempty"`
}

// VPCOptions are vPC domain options beyond the relational vPC model.
type VPCOptions struct {
	AutoRecovery    bool `json:"auto_recovery,omitempty"`
	DelayRestore    *int `json:"delay_restore,omitempty"`
	ARPSynchronize  bool `json:"arp_synchronize,omitempty"`
	NDSynchronize   bool `json:"nd_synchronize,omitempty"`
	FastConvergence bool `json:"fast_convergence,omitempty"`
}

// Operations are operational statements: management servers, trunk and
// relay settings, vPC options and VLAN names. Credentials are never kept.
type Operations struct {
	NTPServers     []Server            `json:"ntp_servers,omitempty"`
	LoggingServers []Server            `json:"logging_servers,omitempty"`
	TACACSServers  []Server            `json:"tacacs_servers,omitempty"`
	SNMPHosts      []Server            `json:"snmp_hosts,omitempty"`
	NVEInfraVLANs  string              `json:"nve_infra_vlans,omitempty"`
	VLANNames      map[string]string   `json:"vlan_names,omitempty"`
	TrunkAllowed   map[string]string   `json:"trunk_allowed,omitempty"` // interface -> range list, "all", "none" or "unknown"
	DHCPRelays     map[string][]Server `json:"dhcp_relays,omitempty"`   // SVI -> relay servers
	FabricPorts    []string            `json:"fabric_ports,omitempty"`
	VPC            *VPCOptions         `json:"vpc,omitempty"`
}

// Breakout is a port breakout declaration.
type Breakout struct {
	ModuleID int    `json:"module_id"`
	Port     int    `json:"port"`
	Map      string `json:"map"`
}

// Interface is any configured interface, including SVIs ("Vlan10"),
// loopbacks, physical ports and port-channels.
type Interface struct {
	Description         string            `json:"description,omitempty"`
	Shutdown            *bool             `json:"shutdown,omitempty"`
	MTU                 *int              `json:"mtu,omitempty"`
	VRF                 string            `json:"vrf,omitempty"`
	Addresses           []string          `json:"addresses,omitempty"`
	Anycast             bool              `json:"anycast,omitempty"`
	IPForward           bool              `json:"ip_forward,omitempty"`
	UnnumberedInterface string            `json:"unnumbered_interface,omitempty"`
	ACLBindings         map[string]string `json:"acl_bindings,omitempty"` // direction (in|out) -> ACL
	OSPF                string            `json:"ospf,omitempty"`
	OSPFNetworkType     string            `json:"ospf_network_type,omitempty"`
	Switchport          *bool             `json:"switchport,omitempty"`
	SwitchportMode      string            `json:"switchport_mode,omitempty"`
	AccessVLAN          *int              `json:"access_vlan,omitempty"`
	ChannelGroup        *int              `json:"channel_group,omitempty"`
	VPCID               *int              `json:"vpc_id,omitempty"`
	PeerLink            bool              `json:"peer_link,omitempty"`
}

// RouteTarget is one route-target statement.
type RouteTarget struct {
	Direction     string `json:"direction"` // import, export, both
	Target        string `json:"target"`
	EVPN          bool   `json:"evpn"`
	AddressFamily string `json:"address_family,omitempty"`
}

// VRFExport is one "export vrf default" statement.
type VRFExport struct {
	VRF           string `json:"vrf"`
	PrefixLimit   *int   `json:"prefix_limit"`
	RouteMap      string `json:"route_map"`
	AllowVPN      bool   `json:"allow_vpn"`
	AddressFamily string `json:"address_family"`
}

// VRF is a VRF context.
type VRF struct {
	VNI          *int          `json:"vni,omitempty"`
	RD           string        `json:"rd,omitempty"`
	RouteTargets []RouteTarget `json:"route_targets"`
	Exports      []VRFExport   `json:"exports,omitempty"`
	Routes       []StaticRoute `json:"routes"`
}

// NVE is the nve1 interface.
type NVE struct {
	Interface            string               `json:"interface,omitempty"`
	Description          string               `json:"description,omitempty"`
	Shutdown             *bool                `json:"shutdown,omitempty"`
	SourceInterface      string               `json:"source_interface,omitempty"`
	HostReachability     string               `json:"host_reachability,omitempty"`
	AdvertiseVirtualRMAC bool                 `json:"advertise_virtual_rmac,omitempty"`
	MulticastGroup       string               `json:"multicast_group,omitempty"` // global mcast-group
	Members              map[string]NVEMember `json:"members"`                   // VNI -> member
}

// NVEMember is one "member vni" under nve1.
type NVEMember struct {
	AssociateVRF   bool   `json:"associate_vrf,omitempty"`
	Replication    string `json:"replication,omitempty"` // bgp, static, multicast
	MulticastGroup string `json:"multicast_group,omitempty"`
	SuppressARP    *bool  `json:"suppress_arp,omitempty"`
}

// EVPNInstance is one "evpn / vni N l2" instance.
type EVPNInstance struct {
	Type         string        `json:"type,omitempty"`
	RD           string        `json:"rd,omitempty"`
	RouteTargets []RouteTarget `json:"route_targets"`
	Routes       []StaticRoute `json:"routes"`
}

// RoutingNode is one level of "router bgp" or "router ospf": the process
// itself, a VRF, a neighbor, a peer template or an address family. NX-OS
// nests these freely, so one recursive type models all of them.
type RoutingNode struct {
	ASN                  *int                   `json:"asn,omitempty"`
	RouterID             string                 `json:"router_id,omitempty"`
	RemoteAS             string                 `json:"remote_as,omitempty"`
	InheritPeer          string                 `json:"inherit_peer,omitempty"`
	UpdateSource         string                 `json:"update_source,omitempty"`
	Description          string                 `json:"description,omitempty"`
	BFD                  *bool                  `json:"bfd,omitempty"`
	RouteReflectorClient *bool                  `json:"route_reflector_client,omitempty"`
	AdvertisePIP         *bool                  `json:"advertise_pip,omitempty"`
	AdvertiseL2VPNEVPN   *bool                  `json:"advertise_l2vpn_evpn,omitempty"`
	NextHopSelf          *bool                  `json:"next_hop_self,omitempty"`
	NextHopSelfAll       *bool                  `json:"next_hop_self_all,omitempty"`
	StandardCommunity    *bool                  `json:"standard_community,omitempty"`
	ExtendedCommunity    *bool                  `json:"extended_community,omitempty"`
	RetainRouteTarget    string                 `json:"retain_route_target,omitempty"`
	RouteMaps            map[string]string      `json:"route_maps,omitempty"` // direction -> route-map
	Networks             []Network              `json:"networks,omitempty"`
	Redistribute         []Redistribution       `json:"redistribute"`
	VRFs                 map[string]RoutingNode `json:"vrfs"`
	Neighbors            map[string]RoutingNode `json:"neighbors"`
	Templates            map[string]RoutingNode `json:"templates"`
	AddressFamilies      map[string]RoutingNode `json:"address_families"`
}

// Network is a BGP network statement.
type Network struct {
	Prefix   string `json:"prefix"`
	RouteMap string `json:"route_map,omitempty"`
}

// Redistribution is one redistribute statement.
type Redistribution struct {
	Protocol string `json:"protocol"`
	Process  string `json:"process,omitempty"`
	RouteMap string `json:"route_map"`
}

// VPCDomain is the vPC domain configuration.
type VPCDomain struct {
	ID               int               `json:"id"`
	PeerKeepalive    map[string]string `json:"peer_keepalive"`    // destination, source, vrf
	VirtualPeerLink  map[string]string `json:"virtual_peer_link"` // destination, source, dscp
	PeerGateway      bool              `json:"peer_gateway"`
	PeerSwitch       bool              `json:"peer_switch"`
	Layer3PeerRouter bool              `json:"layer3_peer_router"`
}

// PrefixListRule is one prefix-list entry.
type PrefixListRule struct {
	Sequence int    `json:"sequence"`
	Action   string `json:"action"`
	Prefix   string `json:"prefix"`
	GE       *int   `json:"ge"`
	LE       *int   `json:"le"`
}

// PrefixListMatch is one "match ip address prefix-list" clause.
type PrefixListMatch struct {
	AddressFamily string   `json:"address_family"`
	Selector      string   `json:"selector"` // address, next-hop, route-source
	Names         []string `json:"names"`
}

// RouteMapEntry is one route-map sequence.
type RouteMapEntry struct {
	Sequence          int               `json:"sequence"`
	Action            string            `json:"action"`
	PrefixLists       []string          `json:"prefix_lists"`
	PrefixListMatches []PrefixListMatch `json:"prefix_list_matches,omitempty"`
	AdditionalMatches []string          `json:"additional_matches"`
	Sets              []string          `json:"sets"`
}

// ACLEntry is one access-list entry.
type ACLEntry struct {
	Sequence   int    `json:"sequence"`
	Action     string `json:"action"` // permit, deny, remark
	Expression string `json:"expression"`
}

// StaticRoute is one "ip route" statement.
type StaticRoute struct {
	Prefix  string `json:"prefix"`
	NextHop string `json:"next_hop"`
	Options string `json:"options"`
}

// Segment is a derived L2/L3 service: one SVI with a VNI and a gateway.
type Segment struct {
	VLANID      int               `json:"vlan_id"`
	VNI         int               `json:"vni"`
	VRF         string            `json:"vrf"`
	Prefix      string            `json:"prefix"`
	Gateway     string            `json:"gateway"`
	Anycast     bool              `json:"anycast"`
	ACLBindings map[string]string `json:"acl_bindings,omitempty"`
}

// RelationFinding is a configuration relation problem the parser derived,
// such as a VLAN mapped to a VNI without an NVE member.
type RelationFinding struct {
	Code     string `json:"code"`
	VNI      *int   `json:"vni,omitempty"`
	VRF      string `json:"vrf,omitempty"`
	EVPNType string `json:"evpn_type,omitempty"`
	VLANIDs  []int  `json:"vlan_ids,omitempty"`
}

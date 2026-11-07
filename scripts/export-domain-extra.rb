# Run with the same Ruby bundle/environment as export-domain-corpus.rb.
require_relative 'export-domain-corpus'
[ nil, {}, { 'z' => '<>&中文', 'a' => "line\u2028paragraph\u2029", 'b' => [ 1, true, nil ] },
  { 'text' => '\\u2028', 'nested' => { 'b' => 2, 'a' => 1 } } ].each { |value| Vxlan::ChangePlan.fingerprint(value) }
[ {}, { 'snapshot' => { 'dimensions' => { 'collection' => { 'status' => 'failed' } } } },
  { 'snapshot' => { 'dimensions' => { 'nve_vnis' => { 'status' => 'partial', 'records' => [ { 'state' => 'Down', 'vni' => 10008 } ], 'issues' => [ { 'code' => 'output_incomplete' } ] },
    'bgp_neighbors' => { 'status' => 'complete', 'records' => [ { 'state' => 'OpenConfirm' } ] } } } } ].each { |doc| Vxlan::Recommendations.new(doc).call }
[ {}, { 'fabrics' => {} }, { 'fabrics' => { 'A' => { 'leaves' => ['192.0.2.1'] } } },
  { 'fabrics' => { 'A' => { 'unknown' => ['192.0.2.1', '192.0.2.2'] } } },
  { 'fabrics' => { 'A' => { 'leaves' => ['2001:0db8::1', '2001:db8::2'] } } },
  { 'fabrics' => { 'A' => { 'leaves' => '192.0.2.1' } } },
  { 'fabrics' => { 'A' => { 'leaves' => ['2001:db8::1','2001:db8::2'] } } } ].each do |policy|
  begin Vxlan::Fabric::Scope.new(policy); rescue ArgumentError; end
end
config = { 'vlan_vnis' => { '8' => 10008, '9' => 10009, '10' => nil }, 'interfaces' => {
 'Vlan8' => { 'vrf' => 'tenant', 'addresses' => ['192.0.2.1/24','2001:db8::1/64'] },
 'Vlan9' => { 'vrf' => 'tenant', 'addresses' => ['192.0.0.1/16','192.0.2.129/25','192.0.2.129/25'] },
 'Vlan10' => { 'vrf' => 'other', 'addresses' => ['invalid'] },
 'Ethernet1/1' => { 'vrf' => 'tenant', 'addresses' => ['invalid'] } } }
index = Vxlan::SubnetIndex.new(config)
[ ['192.0.2.254/24','tenant',10008,nil],['192.0.2.254/32','tenant',10008,'Vlan9'],
 ['2001:db8::ff/64','tenant',10009,nil],['192.0.2.1/24','other',10008,nil],['invalid','tenant',10008,nil] ].each do |address,vrf,vni,except|
 begin index.conflicts(address: address, vrf: vrf, vni: vni, except_interface: except);rescue ArgumentError;end
end
bgp = { asn: 65001, templates: { 'BASE' => { remote_as: 65002, address_families: { 'ipv4 unicast' => { route_maps: { in: 'IN', out: 'OUT' }, send_community: 'both' } } },
 'CHAIN' => { inherit_peer: 'BASE' } }, neighbors: {
 '192.0.2.1' => { inherit_peer: 'BASE', remote_as: nil, address_families: { 'ipv4 unicast' => { route_maps: { in: 'OVERRIDE' }, send_community: nil } } },
 '192.0.2.2' => { inherit_peer: 'missing' }, '192.0.2.3' => { inherit_peer: 'CHAIN' } },
 address_families: { 'ipv4 unicast' => { redistribute: [ { protocol: 'ospf', process: 'UNDERLAY', route_map: 'OUT' } ], retain_route_target: 'route-map OUT' } },
 vrfs: { 'tenant' => { neighbors: { '198.51.100.1' => { remote_as: 65010 } } } } }
DomainCorpus.capture('bgp_neighbors',bgp: bgp) { Vxlan::BgpNeighbors.new(bgp).to_a }
routing = { bgp: bgp, route_maps: { 'IN' => [{ sequence: 10, action: 'permit', prefix_lists: ['V4'] }],
 'OUT' => [{ sequence: 10, action: 'permit', prefix_list_matches: [ { address_family: 'ipv6', selector: 'next-hop', names: ['V6','V6'] } ] }],
 'OVERRIDE' => [{ sequence: 10, action: 'permit', prefix_list_matches: [{ address_family: 'ipv4', selector: 'route-source', names: ['V4'] }] }] },
 ospf: { 'UNDERLAY' => { redistribute: [{ protocol: 'static', route_map: 'OUT' }], vrfs: { 'tenant' => { redistribute: [{ protocol: 'bgp', process: '65001', route_map: 'IN' }] } } } },
 vrfs: { 'tenant' => { exports: [{ address_family: 'ipv4 unicast', vrf: 'default', route_map: 'IN' }] } } }
%w[ipv4 ipv6].each { |family| Vxlan::PrefixListReferences.new(routing).call(address_family: family) }
begin Vxlan::PrefixListReferences.new(routing).call(address_family: 'invalid');rescue ArgumentError;end
# The gateway action is not built in the standalone change-plan specs.
change = { 'kind' => 'svi_gateway_add', 'vlan' => 8, 'vni' => 10008, 'vrf' => 'tenant', 'address' => '192.0.2.254/24' }
before = { 'vlan_vnis' => { '8' => 10008 }, 'interfaces' => { 'Vlan8' => { 'vrf' => 'tenant', 'anycast' => true, 'addresses' => [] } } }
plan = Vxlan::ChangePlan.build(change)
plan.eligible?(before)
after = Marshal.load(Marshal.dump(before));after['interfaces']['Vlan8']['addresses'] << change['address']
plan.satisfied?(after,before: before)
after['interfaces']['Vlan8']['mtu'] = 9216;plan.satisfied?(after,before: before)

package fabric_test

import (
	"encoding/json"
	"testing"

	"github.com/gatework/go-netops/evidence"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

func TestBGPSummaryDocument(t *testing.T) {
	text := "BGP summary information for VRF BLUE, address family L2VPN EVPN\n" +
		"BGP table version is 18446744073709551616, L2VPN EVPN config peers 2, capable peers 1\n" +
		"Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd\n" +
		"192.0.2.2 4 65001 10 20 1 0 0 1d 12\n"
	o, err := nxos.ParseRuntime("bgp_neighbors", text, true)
	if err != nil {
		t.Fatal(err)
	}
	o.Evidence = append(o.Evidence, vxlan.Record{"command": "show bgp l2vpn evpn summary", "sha256": "wire"})
	d, err := fabric.EncodeDocument(map[string]any{
		"device":   map[string]any{"host": "fixture"},
		"snapshot": map[string]any{"dimensions": map[string]any{"bgp_neighbors": o}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Has(fabric.DimBGP) || len(d.BGPSummaries) != 1 || len(d.BGPNeighbors) != 1 {
		t.Fatalf("summary lost at typed boundary: %+v", d)
	}
	if d.BGPSummaries[0].TableVersion != json.Number("18446744073709551616") || d.BGPSummaries[0].Line != 2 {
		t.Fatal(d.BGPSummaries)
	}
	raw := json.RawMessage(`{"kind":"bgp_summary","vrf":"BLUE","address_family":"L2VPN EVPN","future":true}`)
	d = fabric.NewDevice(fabric.Identity{Host: "fixture"}, map[evidence.Dimension]fabric.Observed{
		fabric.DimBGP: {Status: evidence.StatusComplete, Evidence: []json.RawMessage{raw}},
	})
	if d.Has(fabric.DimBGP) || len(d.BGPSummaries) != 0 {
		t.Fatal("unknown summary fields silently accepted")
	}
}

package nxos

import (
	"fmt"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
)

func TestConfigReviewRegressions(t *testing.T) {
	for _, name := range []string{"Vlan0", "Vlan5000", "Vlan999999999999999999999999"} {
		if !ParseConfig("hostname LEAF\ninterface "+name+"\n", true).Complete() {
			t.Fatal(name)
		}
	}
	o := ParseConfig("banner motd é\nê\nhostname FAKE\né\nhostname REAL\n", true)
	if !o.Complete() || o.Records[0]["hostname"] != "REAL" {
		t.Fatal(o, o.Issues)
	}
	o = ParseConfig("hostname LEAF\n!comment\nignored\v\n", true)
	if o.Records[0]["config_digest"] != "808fa7029f22051df01465d7ba5914fdf30e1d3ba157425f7e21ba27a9515fff" {
		t.Fatal(o.Records)
	}
	if ParseConfig("\u00a0hostname LEAF\n", true).Complete() {
		t.Fatal("unicode whitespace accepted")
	}
	for range 100 {
		o = ParseConfig("hostname LEAF\nvrf context Z\n  vni 10000\nvrf context A\n  vni 10000\n", true)
		f := o.Records[0]["review_findings"].([]vxlan.Record)
		if f[0]["vrf"] != "Z" || f[1]["vrf"] != "A" {
			t.Fatal(f)
		}
	}
	ids := []int{10}
	labels := map[string]string{"key": "before"}
	o, _ = vxlan.NewObservation("configuration", "complete", []vxlan.Record{{"ids": ids, "labels": labels}}, nil, nil)
	ids[0] = 20
	labels["key"] = "after"
	if fmt.Sprint(o.Records[0]["ids"]) != "[10]" || fmt.Sprint(o.Records[0]["labels"]) != "map[key:before]" {
		t.Fatal("alias")
	}
}

package nxos

import (
	vxlan "github.com/gatework/go-vxlan"
)

func observation(name, status string, rows, issues []vxlan.Record) vxlan.Observation {
	o, _ := vxlan.NewObservation(name, status, rows, issues, nil)
	return o
}

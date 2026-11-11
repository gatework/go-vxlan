package bootstrap

import (
	"context"
	"fmt"
	"slices"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/collect"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/internal/workflow"
	"github.com/gatework/go-vxlan/vendors"
)

// Collection binds an owned runtime snapshot to the selected connection adapter.
// Credentials and process resource limits are resolved before any device opens.
func Collection(ctx context.Context, c Config, devices []any, open OpenFunc) (workflow.CollectionOptions, error) {
	connection, err := Credentials(c)
	if err != nil {
		return workflow.CollectionOptions{}, err
	}
	workers := min(c.runtime.Parallel, len(devices))
	if err = PrepareResources(ctx, workers); err != nil {
		return workflow.CollectionOptions{}, fmt.Errorf("并发资源不足")
	}
	var policy vxlan.Record
	if c.runtime.policy != nil {
		var err error
		policy, err = vxlan.ProjectRecord(c.runtime.policy)
		if err != nil {
			return workflow.CollectionOptions{}, err
		}
	}
	dimensions := slices.Clone(c.runtime.Dimensions)
	fabric := record.Copy(c.runtime.FabricKey)
	registry := vendors.NewBuiltinRegistry()
	queries, err := registry.Fetch("cisco_nxos", "")
	if err != nil {
		return workflow.CollectionOptions{}, err
	}
	return workflow.CollectionOptions{
		Devices:   record.Clone(devices),
		Directory: c.runtime.Directory,
		Workers:   workers,
		Policy:    policy,
		Queries:   queries,
		Collect: func(ctx context.Context, device vxlan.Record) (vxlan.Snapshot, error) {
			profile, err := registry.Fetch("cisco_nxos", record.String(device["model"]))
			if err != nil {
				return vxlan.Snapshot{}, err
			}
			settings := connection
			settings.Host = record.String(device["host"])
			return collect.Collect(ctx, open(settings), collect.Request{
				Target: device, FabricKey: fabric, Profile: profile, Dimensions: dimensions,
			})
		},
	}, nil
}

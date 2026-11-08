package netconnector

import (
	"context"
	"errors"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/collect"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

type ConfigurationSession struct{ collect.Session }

func (s ConfigurationSession) ReadConfiguration(ctx context.Context) (vxlan.Record, error) {
	if s.Session == nil {
		return nil, change.ErrExecutionPlan
	}
	for _, command := range nxos.ProfileSpec().Preparation {
		capture, err := s.Read(ctx, command)
		if err != nil || !capture.Complete {
			return nil, errors.Join(change.ErrExecutionPlan, err)
		}
	}
	capture, err := s.Read(ctx, nxos.Commands()["configuration"])
	if err != nil || !capture.Complete {
		return nil, errors.Join(change.ErrExecutionPlan, err)
	}
	observation := nxos.ParseConfig(capture.Body, true)
	if !observation.Complete() || len(observation.Records) != 1 {
		return nil, change.ErrExecutionPlan
	}
	return vxlan.ProjectRecord(observation.Records[0])
}

func (s ConfigurationSession) Write(ctx context.Context, command string) error {
	writer, ok := s.Session.(interface {
		Write(context.Context, string) error
	})
	if !ok {
		return change.ErrExecutionPlan
	}
	return writer.Write(ctx, command)
}

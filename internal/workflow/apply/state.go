package apply

import (
	"slices"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/change"
)

type executionStatus string

const (
	executionConfirmed executionStatus = "confirmed"
	executionRunning   executionStatus = "executing"
	executionFailed    executionStatus = "failed"
	executionUncertain executionStatus = "uncertain"
	executionVerified  executionStatus = "configuration_verified"
)

// executionState owns the mutable facts of one admitted execution. The bound
// plan is immutable; journals and callers only receive detached projections.
type executionState struct {
	plan                 *change.ExecutionPlan
	commands             []string
	status               executionStatus
	pendingCommand       *int
	acknowledged         []int
	observedConfigSHA256 string
	errorCode            string
	started, verified    bool
}

func (s *executionState) record() vxlan.Record {
	steps := make([]vxlan.Record, len(s.acknowledged))
	for i, index := range s.acknowledged {
		steps[i] = vxlan.Record{"index": index, "status": "acknowledged"}
	}
	out := vxlan.Record{
		"status": string(s.status), "device": s.plan.Device(),
		"plan_sha256": s.plan.PlanSHA256(), "plan_item": s.plan.ItemID(),
		"expected_config_sha256": s.plan.ExpectedConfigSHA256(),
		"commands":               slices.Clone(s.commands), "steps": steps,
	}
	if s.pendingCommand != nil {
		out["pending_command"] = *s.pendingCommand
	}
	if s.observedConfigSHA256 != "" {
		out["observed_config_sha256"] = s.observedConfigSHA256
	}
	if s.errorCode != "" {
		out["error"] = s.errorCode
	}
	return out
}

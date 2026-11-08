package vxlan

import (
	"fmt"
	"time"

	"github.com/gatework/go-vxlan/internal/record"
)

type Record = map[string]any

type Observation struct {
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	Records     []Record   `json:"records"`
	Issues      []Record   `json:"issues"`
	Evidence    []Record   `json:"evidence"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
}

func NewObservation(name, status string, records, issues, evidence []Record) (Observation, error) {
	if name == "" {
		return Observation{}, fmt.Errorf("empty observation name")
	}
	switch status {
	case "complete", "partial", "failed", "unsupported", "not_requested":
	default:
		return Observation{}, fmt.Errorf("invalid observation status")
	}
	if _, err := ProjectRecord(Record{"records": records, "issues": issues, "evidence": evidence}); err != nil {
		return Observation{}, err
	}
	return Observation{Name: name, Status: status, Records: record.CopyRecords(records), Issues: record.CopyRecords(issues), Evidence: record.CopyRecords(evidence)}, nil
}
func (o Observation) Complete() bool { return o.Status == "complete" }
func (o Observation) String() string {
	return fmt.Sprintf("Observation{name=%s status=%s records=%d}", o.Name, o.Status, len(o.Records))
}
func (o Observation) GoString() string { return o.String() }

type Snapshot struct {
	Target     Record                 `json:"target"`
	FabricKey  any                    `json:"fabric_key"`
	Dimensions map[string]Observation `json:"dimensions"`
	ObservedAt *time.Time             `json:"observed_at"`
}

func (s Snapshot) Complete() bool {
	n := 0
	for _, o := range s.Dimensions {
		if o.Status == "not_requested" {
			continue
		}
		n++
		if !o.Complete() {
			return false
		}
	}
	return n > 0
}
func (s Snapshot) String() string {
	return fmt.Sprintf("Snapshot{complete=%t dimensions=%d}", s.Complete(), len(s.Dimensions))
}
func (s Snapshot) GoString() string { return s.String() }

package change

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

var ErrExecutionPlan = errors.New("vxlan: execution plan validation failed")

var executionItemID = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var configurationDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ExecutionPlan owns one selected item, its exact source-file identity and its
// rendered business increment. Construct it after authenticating the file's
// checksum, then confirm its token before opening a session. Accessors return
// copies; modifying the source bytes or presentation cannot change execution.
type ExecutionPlan struct {
	itemID, planSHA256, expectedSHA256 string
	device, presentation               vxlan.Record
	change                             *ChangePlan
}

func NewExecutionPlan(body []byte, itemID string) (*ExecutionPlan, error) {
	if !executionItemID.MatchString(itemID) {
		return nil, ErrExecutionPlan
	}
	document, err := vxlan.DecodeDocument(body)
	if err != nil || !record.Integer(document["schema_version"], 2, 2) || document["platform"] != "cisco_nxos" {
		return nil, ErrExecutionPlan
	}
	item, ok := record.Map(document["changes"])[itemID].(vxlan.Record)
	if !ok || !record.Integer(item["schema_version"], 1, 1) || item["platform"] != "cisco_nxos" {
		return nil, ErrExecutionPlan
	}
	device, ok := item["device"].(vxlan.Record)
	if !ok {
		return nil, ErrExecutionPlan
	}
	host, _ := device["host"].(string)
	address, err := netip.ParseAddr(host)
	expected, _ := item["expected_config_sha256"].(string)
	if err != nil || address.String() != host || !configurationDigest.MatchString(expected) {
		return nil, ErrExecutionPlan
	}
	change, err := NewChangePlan(record.Map(item["change"]))
	if err != nil {
		return nil, ErrExecutionPlan
	}
	for key, rendered := range map[string][]string{"commands": change.Commands(), "rollback": change.Rollback()} {
		values, ok := record.Strings(item[key])
		if !ok || !slices.Equal(values, rendered) {
			return nil, ErrExecutionPlan
		}
	}
	return &ExecutionPlan{itemID: itemID, planSHA256: fmt.Sprintf("%x", sha256.Sum256(body)), expectedSHA256: expected, device: record.Copy(device).(vxlan.Record), presentation: record.Copy(item).(vxlan.Record), change: change}, nil
}

func (p *ExecutionPlan) Valid() bool                  { return p != nil && p.change != nil && p.planSHA256 != "" }
func (p *ExecutionPlan) Host() string                 { return record.String(p.device["host"]) }
func (p *ExecutionPlan) ItemID() string               { return p.itemID }
func (p *ExecutionPlan) PlanSHA256() string           { return p.planSHA256 }
func (p *ExecutionPlan) ExpectedConfigSHA256() string { return p.expectedSHA256 }
func (p *ExecutionPlan) Device() vxlan.Record {
	return record.Copy(p.device).(vxlan.Record)
}
func (p *ExecutionPlan) Presentation() vxlan.Record {
	return record.Copy(p.presentation).(vxlan.Record)
}
func (p *ExecutionPlan) Commands() []string { return p.change.Commands() }
func (p *ExecutionPlan) Rollback() []string { return p.change.Rollback() }
func (p *ExecutionPlan) ConfirmationToken() string {
	return "APPLY " + p.Host() + " " + p.planSHA256[:12] + " " + p.itemID
}

func (p *ExecutionPlan) CheckBefore(config vxlan.Record) error {
	if !p.Valid() {
		return ErrExecutionPlan
	}
	checked, err := vxlan.ProjectRecord(config)
	if err != nil {
		return err
	}
	if checked["review_status"] != "complete" {
		return ErrExecutionPlan
	}
	if err = vxlan.ValidateConfigurationRecord(checked); err != nil {
		return ErrExecutionPlan
	}
	digest, err := vxlan.Fingerprint(checked)
	if err != nil {
		return err
	}
	if digest != p.expectedSHA256 || !p.change.Eligible(checked) {
		return ErrExecutionPlan
	}
	return nil
}

func (p *ExecutionPlan) CheckAfter(before, after vxlan.Record) (string, error) {
	if err := p.CheckBefore(before); err != nil {
		return "", err
	}
	checked, err := vxlan.ProjectRecord(after)
	if err != nil {
		return "", err
	}
	if checked["review_status"] != "complete" {
		return "", ErrExecutionPlan
	}
	if err = vxlan.ValidateConfigurationRecord(checked); err != nil {
		return "", ErrExecutionPlan
	}
	if !p.change.Satisfied(checked, before) {
		return "", ErrExecutionPlan
	}
	return vxlan.Fingerprint(checked)
}

package change

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/fabric"
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
	change                             Change
	commands, rollback                 []string
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
	changeBody, err := json.Marshal(item["change"])
	if err != nil {
		return nil, ErrExecutionPlan
	}
	change, err := DecodeChange(changeBody)
	if err != nil {
		return nil, ErrExecutionPlan
	}
	script, err := change.Render()
	if err != nil {
		return nil, ErrExecutionPlan
	}
	for key, rendered := range map[string][]string{"commands": script.Commands, "rollback": script.Rollback} {
		values, ok := record.Strings(item[key])
		if !ok || !slices.Equal(values, rendered) {
			return nil, ErrExecutionPlan
		}
	}
	return &ExecutionPlan{itemID: itemID, planSHA256: fmt.Sprintf("%x", sha256.Sum256(body)), expectedSHA256: expected, device: record.Copy(device).(vxlan.Record), presentation: record.Copy(item).(vxlan.Record), change: change,
		commands: script.Commands, rollback: script.Rollback}, nil
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
func (p *ExecutionPlan) Commands() []string { return slices.Clone(p.commands) }
func (p *ExecutionPlan) Rollback() []string { return slices.Clone(p.rollback) }
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
	if digest != p.expectedSHA256 {
		return ErrExecutionPlan
	}
	typed, err := typedConfiguration(checked)
	if err != nil || p.change.Eligible(typed) != nil {
		return ErrExecutionPlan
	}
	return nil
}

// typedConfiguration decodes a checked configuration record into the typed
// model; unknown fields are rejected so they cannot pass unexamined.
func typedConfiguration(config vxlan.Record) (*fabric.Configuration, error) {
	body, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return fabric.DecodeConfiguration(body)
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
	typedBefore, err := typedConfiguration(before)
	if err != nil {
		return "", ErrExecutionPlan
	}
	typedAfter, err := typedConfiguration(checked)
	if err != nil || p.change.Satisfied(typedAfter) != nil || p.change.Preserved(typedBefore, typedAfter) != nil {
		return "", ErrExecutionPlan
	}
	return vxlan.Fingerprint(checked)
}

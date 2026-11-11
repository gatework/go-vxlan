package change_test

import (
	"encoding/json"

	vxlan "github.com/gatework/go-vxlan"
	changepkg "github.com/gatework/go-vxlan/change"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/internal/record"
)

// renderedChange gives tests the change record, commands and rollback of a
// typed increment, as the former ChangePlan accessors did.
type renderedChange struct {
	change             vxlan.Record
	commands, rollback []string
	typed              changepkg.Change
}

// Eligible applies the typed eligibility check to a configuration record.
func (r renderedChange) Eligible(config vxlan.Record) bool {
	body, err := json.Marshal(config)
	if err != nil {
		return false
	}
	c, err := fabric.DecodeConfiguration(body)
	return err == nil && r.typed.Eligible(c) == nil
}

// Satisfied applies the typed readback checks: before is eligible, after
// shows the change, and nothing else changed.
func (r renderedChange) Satisfied(after, before vxlan.Record) bool {
	decode := func(v vxlan.Record) *fabric.Configuration {
		body, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		c, err := fabric.DecodeConfiguration(body)
		if err != nil {
			return nil
		}
		return c
	}
	a, b := decode(after), decode(before)
	return a != nil && b != nil && r.typed.Eligible(b) == nil && r.typed.Satisfied(a) == nil && r.typed.Preserved(b, a) == nil
}

func (r renderedChange) Change() vxlan.Record { return record.Copy(r.change).(vxlan.Record) }
func (r renderedChange) Commands() []string   { return append([]string{}, r.commands...) }
func (r renderedChange) Rollback() []string   { return append([]string{}, r.rollback...) }

func newChangePlan(rec vxlan.Record) (renderedChange, error) {
	body, err := json.Marshal(rec)
	if err != nil {
		return renderedChange{}, err
	}
	c, err := changepkg.DecodeChange(body)
	if err != nil {
		return renderedChange{}, err
	}
	script, err := c.Render()
	if err != nil {
		return renderedChange{}, err
	}
	m, err := changepkg.Record(c)
	if err != nil {
		return renderedChange{}, err
	}
	projected, err := vxlan.ProjectRecord(m)
	return renderedChange{projected, script.Commands, script.Rollback, c}, err
}

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/go-net-connector/connector"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/collect"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

type applySession struct {
	before, after string
	writes        []string
	fail          bool
}

func (s *applySession) Read(_ context.Context, command string) (collect.Capture, error) {
	body := ""
	if command == "show running-config" {
		body = s.before
		if len(s.writes) > 0 {
			body = s.after
		}
	}
	return collect.Capture{Body: body, Complete: true}, nil
}
func (s *applySession) Write(_ context.Context, command string) error {
	s.writes = append(s.writes, command)
	if s.fail {
		return errors.New("private detail")
	}
	return nil
}
func TestApplyBoundaries(t *testing.T) {
	for _, mode := range []string{"success", "drift", "write_failure", "readback_failure", "close_failure", "missing_callback", "duplicate_callback", "bad_checksum", "extra_command", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			before := "hostname LEAF\nvlan 8\n  vn-segment 10008\ninterface Vlan8\n  vrf member tenant\n  fabric forwarding mode anycast-gateway\n"
			after := before + "  ip address 192.0.2.254/24\n"
			config := normalize(nxos.ParseConfig(before, true).Records[0])
			change := vxlan.Record{"kind": "svi_gateway_add", "vlan": 8, "vni": 10008, "vrf": "tenant", "address": "192.0.2.254/24"}
			cp, e := newChangePlan(change)
			if e != nil {
				t.Fatal(e)
			}
			if !cp.Eligible(config) {
				t.Fatal("fixture ineligible")
			}
			commands := []any{}
			for _, s := range cp.Commands() {
				commands = append(commands, s)
			}
			if mode == "extra_command" {
				commands = append(commands, 7)
			}
			plan := vxlan.Record{"schema_version": 2, "platform": "cisco_nxos", "changes": vxlan.Record{"test": vxlan.Record{"schema_version": 1, "platform": "cisco_nxos", "device": vxlan.Record{"name": "LEAF", "host": "192.0.2.1"}, "expected_config_sha256": fingerprint(config), "change": change, "commands": commands, "rollback": cp.Rollback(), "title": "gateway", "scope": "VLAN 8", "impact": "test", "prerequisites": []string{}}}}
			body := jsonBytes(plan)
			hash := fmt.Sprintf("%x", sha256.Sum256(body))
			path := filepath.Join(d, "plan.json")
			os.WriteFile(path, body, 0600)
			checksum := hash
			if mode == "bad_checksum" {
				checksum = "bad"
			}
			os.WriteFile(path+".sha256", []byte(checksum), 0600)
			token := "APPLY 192.0.2.1 " + hash[:12] + " test\n"
			if mode == "cancel" {
				token = "no\n"
			}
			session := &applySession{before: before, after: after, fail: mode == "write_failure"}
			if mode == "drift" {
				session.before = "hostname CHANGED\n"
			}
			if mode == "readback_failure" {
				session.after = before
			}
			opened := 0
			var out, err bytes.Buffer
			a := App{Input: bytes.NewBufferString(token), Output: &out, Error: &err, CWD: d, Home: d, Directories: []string{}, Environment: map[string]string{"NC_DEVICE_USERNAME": "test"}, Terminal: func() bool { return true }, Open: func(connector.ConnectionConfig) collect.OpenSession {
				return func(ctx context.Context, fn func(context.Context, collect.Session) error) error {
					opened++
					if mode == "missing_callback" {
						return nil
					}
					e := fn(ctx, session)
					if e != nil {
						return e
					}
					if mode == "duplicate_callback" {
						return fn(ctx, session)
					}
					if mode == "close_failure" {
						return errors.New("private close detail")
					}
					return nil
				}
			}}
			code := a.Run(context.Background(), []string{"apply", "--plan", path, "--item", "test"})
			want := 2
			if mode == "success" {
				want = 0
			}
			if mode == "cancel" {
				want = 1
			}
			if code != want {
				t.Fatalf("code=%d want=%d stderr=%s", code, want, err.String())
			}
			if mode == "bad_checksum" || mode == "extra_command" || mode == "cancel" {
				if opened != 0 {
					t.Fatal("preflight connected")
				}
			}
			if mode == "write_failure" && len(session.writes) != 1 {
				t.Fatal("replayed failed write")
			}
			if mode == "duplicate_callback" && len(session.writes) != len(cp.Commands()) {
				t.Fatal("replayed operation")
			}
			paths, _ := filepath.Glob(filepath.Join(d, "vxlan-executions", "*", "execution.json"))
			if len(paths) > 0 {
				b, _ := os.ReadFile(paths[0])
				var journal vxlan.Record
				json.Unmarshal(b, &journal)
				status := journal["status"]
				if mode == "success" && status != "configuration_verified" {
					t.Fatal(status)
				}
				if mode == "write_failure" || mode == "readback_failure" || mode == "close_failure" || mode == "duplicate_callback" {
					if status != "uncertain" {
						t.Fatal(status)
					}
				}
			}
			if bytes.Contains(err.Bytes(), []byte("private")) {
				t.Fatal("raw error leaked")
			}
		})
	}
}

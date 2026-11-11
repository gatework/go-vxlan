package netconnector

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gatework/go-net-connector/connector"
	"github.com/gatework/go-net-connector/vendors"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

func TestDeliveryReviewerReadPinsCurrentPrompt(t *testing.T) {
	platform, e := vendors.NewBuiltinRegistry().Lookup("cisco_nxos")
	if e != nil {
		t.Fatal(e)
	}
	device, e := connector.New(platform, connector.ConnectionConfig{Host: "fixture", LoginTimeout: time.Second, CommandTimeout: time.Second}, connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			io.WriteString(b, "leaf#")
			reader := bufio.NewReader(b)
			reader.ReadString('\n')
			io.WriteString(b, "show running-config\r\nhostname LEAF\r\n!comment#")
			time.Sleep(50 * time.Millisecond)
			io.WriteString(b, "\r\nfeature nv overlay\r\nleaf#")
			io.Copy(io.Discard, b)
		}()
		return a, nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	defer device.Close()
	if e = device.Connect(t.Context()); e != nil {
		t.Fatal(e)
	}
	e = device.WithOperation(t.Context(), func(ctx context.Context, op *connector.Operation) error {
		capture, err := (Session{Operation: op, Device: device}).Read(t.Context(), "show running-config")
		if err != nil {
			return err
		}
		o := nxos.ParseConfig(capture.Body, capture.Complete)
		if !strings.Contains(capture.Body, "feature nv overlay") {
			t.Errorf("truncated body accepted complete=%v parsed=%v body=%q", capture.Complete, o.Complete(), capture.Body)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestReadAcceptsNXOSCarriageReturnPrompt(t *testing.T) {
	for _, ending := range []string{"\rleaf# ", "\r\n\rleaf# ", "\r\nleaf#\r\n"} {
		t.Run(fmt.Sprintf("%q", ending), func(t *testing.T) {
			platform, e := vendors.NewBuiltinRegistry().Lookup("cisco_nxos")
			if e != nil {
				t.Fatal(e)
			}
			device, e := connector.New(platform, connector.ConnectionConfig{Host: "fixture", LoginTimeout: time.Second, CommandTimeout: 100 * time.Millisecond}, connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					io.WriteString(b, "leaf# ")
					reader := bufio.NewReader(b)
					for range 2 {
						command, e := reader.ReadString('\n')
						if e != nil {
							return
						}
						io.WriteString(b, strings.TrimSpace(command)+"\r\r\n"+ending)
					}
					io.Copy(io.Discard, b)
				}()
				return a, nil
			}))
			if e != nil {
				t.Fatal(e)
			}
			defer device.Close()
			if e = device.Connect(t.Context()); e != nil {
				t.Fatal(e)
			}
			e = device.WithOperation(t.Context(), func(ctx context.Context, op *connector.Operation) error {
				session := Session{Operation: op, Device: device}
				for _, command := range []string{"terminal length 0", "terminal width 511"} {
					capture, e := session.Read(t.Context(), command)
					if e != nil {
						return e
					}
					if !capture.Complete {
						return fmt.Errorf("incomplete capture")
					}
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestReadRendersBodyAndRetainsReceiptEvidence(t *testing.T) {
	command := "show nve peers"
	raw := command + "\r\r\n\x1b[32mInterface Peer-IP State\x1b[0m\r\n" + command + "\r\n\rleaf# "
	platform, e := vendors.NewBuiltinRegistry().Lookup("cisco_nxos")
	if e != nil {
		t.Fatal(e)
	}
	device, e := connector.New(platform, connector.ConnectionConfig{Host: "fixture", LoginTimeout: time.Second, CommandTimeout: time.Second}, connector.WithTransportFactory(func(context.Context, connector.ConnectionConfig) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			io.WriteString(b, "leaf# ")
			bufio.NewReader(b).ReadString('\n')
			io.WriteString(b, raw)
			io.Copy(io.Discard, b)
		}()
		return a, nil
	}))
	if e != nil {
		t.Fatal(e)
	}
	defer device.Close()
	if e = device.Connect(t.Context()); e != nil {
		t.Fatal(e)
	}
	e = device.WithOperation(t.Context(), func(ctx context.Context, op *connector.Operation) error {
		capture, e := (Session{Operation: op, Device: device}).Read(t.Context(), command)
		if e != nil {
			return e
		}
		if capture.Body != "Interface Peer-IP State\n"+command+"\n" {
			t.Fatalf("body retains framing or loses repeated content: %q", capture.Body)
		}
		if len(capture.Evidence) != 1 || capture.Evidence[0]["sha256"] != fmt.Sprintf("%x", sha256.Sum256([]byte(raw))) || capture.Evidence[0]["bytes"] != len(raw) {
			t.Fatal("receipt evidence missing or changed")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/go-net-connector/connector"
	"github.com/gatework/go-vxlan/collect"
	"github.com/gatework/go-vxlan/internal/bootstrap"
	"golang.org/x/sys/unix"
)

func TestPrepareResources(t *testing.T) {
	mode := os.Getenv("VXLAN_TEST_RESOURCE_LIMIT")
	if mode == "" {
		for _, mode := range []string{"raise", "insufficient", "no_change", "collect"} {
			t.Run(mode, func(t *testing.T) {
				cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPrepareResources$")
				cmd.Env = append(os.Environ(), "VXLAN_TEST_RESOURCE_LIMIT="+mode)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("isolated limit test: %v\n%s", err, output)
				}
			})
		}
		return
	}
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	if original.Max < 928 {
		t.Skip("test needs a hard descriptor limit of at least 928")
	}
	limit := unix.Rlimit{Cur: 192, Max: original.Max}
	if mode == "insufficient" || mode == "collect" {
		limit.Max = 256
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "raise":
		if err := bootstrap.PrepareResources(t.Context(), 50); err != nil {
			t.Fatal(err)
		}
		var got unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &got); err != nil || got.Cur < 928 || got.Max != original.Max {
			t.Fatalf("limit=%+v error=%v", got, err)
		}
		// Exercise the raised limit with real descriptors.
		for range 450 {
			f, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
		}
	case "insufficient":
		err := bootstrap.PrepareResources(t.Context(), 50)
		if !errors.Is(err, bootstrap.ErrResourceLimit) || !strings.Contains(err.Error(), "50 concurrent devices require at least 928") {
			t.Fatalf("capacity error: %v", err)
		}
	case "no_change":
		for _, parallel := range []int{-1, 501} {
			if err := bootstrap.PrepareResources(t.Context(), parallel); !errors.Is(err, bootstrap.ErrResourceParallel) {
				t.Fatal(err)
			}
		}
		for _, parallel := range []int{0, 4} {
			if err := bootstrap.PrepareResources(t.Context(), parallel); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := bootstrap.PrepareResources(ctx, 50); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case "collect":
		dir := t.TempDir()
		var config strings.Builder
		config.WriteString("parallel: 50\ndevices:\n")
		for i := range 50 {
			fmt.Fprintf(&config, "  - host: 192.0.2.%d\n    name: leaf%d\n    model: N9K\n", i+1, i+1)
		}
		path := filepath.Join(dir, "vxlan.yml")
		if err := os.WriteFile(path, []byte(config.String()), 0600); err != nil {
			t.Fatal(err)
		}
		var output, diagnostic bytes.Buffer
		opened := 0
		app := App{
			CWD: dir, Home: dir, Directories: []string{},
			Environment: map[string]string{"NC_DEVICE_USERNAME": "test"},
			Input:       strings.NewReader(""), Output: &output, Error: &diagnostic,
			Open: func(connector.ConnectionConfig) collect.OpenSession {
				opened++
				return nil
			},
		}
		code := app.Run(t.Context(), []string{"collect", "--config", path, "--non-interactive"})
		if code != 2 || opened != 0 || !strings.Contains(diagnostic.String(), "并发资源不足") {
			t.Fatalf("code=%d opened=%d diagnostic=%q", code, opened, diagnostic.String())
		}
	}
	if mode != "raise" {
		var after unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &after); err != nil || after != limit {
			t.Fatalf("limit changed: %+v -> %+v (%v)", limit, after, err)
		}
	}
}

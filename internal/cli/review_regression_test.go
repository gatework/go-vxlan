package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/bootstrap"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

type forbiddenReader struct{ read bool }

func (r *forbiddenReader) Read([]byte) (int, error) {
	r.read = true
	return 0, errors.New("must not read")
}
func TestReviewInputValidation(t *testing.T) {
	r := vxlan.Record{"review_findings": "BAD"}
	if vxlan.ValidateConfigurationRecord(r) == nil {
		t.Fatal("invalid findings admitted")
	}
}
func TestConfigReviewValidation(t *testing.T) {
	for _, body := range []string{"fabric_policy: 123\n", "common: wrong\nvxlan: wrong\n"} {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "vxlan.yml"), []byte(body), 0600)
		if _, e := bootstrap.Load(t.Context(), bootstrap.ConfigOptions{CWD: d, Home: d, Directories: []string{d}, Environment: map[string]string{}}); e == nil {
			t.Fatal("invalid config accepted", body)
		}
	}
}
func TestBlankSelectorUsesDotenv(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, ".env"), []byte("VXLAN_CONFIG=custom.yml\n"), 0600)
	os.WriteFile(filepath.Join(d, "custom.yml"), []byte("fabric: CUSTOM\n"), 0600)
	c, e := bootstrap.Load(t.Context(), bootstrap.ConfigOptions{CWD: d, Home: d, Directories: []string{d}, Environment: map[string]string{"VXLAN_CONFIG": ""}})
	if e != nil || c.Values["fabric"] != "CUSTOM" {
		t.Fatal(c, e)
	}
}
func TestCLIOutputAndPreflight(t *testing.T) {
	r := &forbiddenReader{}
	a := App{Input: r, Output: &bytes.Buffer{}, Error: &bytes.Buffer{}}
	if a.Run(context.Background(), []string{"parse", "--dimension", "unknown"}) != 2 || r.read {
		t.Fatal("invalid dimension read input")
	}
	a.Output = failWriter{}
	if a.Run(context.Background(), []string{"--help"}) != 2 {
		t.Fatal("help output failure ignored")
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "vxlan.yml"), []byte("devices: []\n"), 0600)
	a = App{Input: r, Output: &bytes.Buffer{}, Error: &bytes.Buffer{}, CWD: d, Home: d, Directories: []string{d}, Environment: map[string]string{}}
	if a.Run(context.Background(), []string{"collect", "--plan"}) != 1 {
		t.Fatal("empty preview succeeded")
	}
}

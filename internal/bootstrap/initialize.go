package bootstrap

import (
	"context"
	"os"
	"path/filepath"

	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/report"
	"go.yaml.in/yaml/v3"
)

// InitializedFile identifies a created template or an existing file preserved in place.
type InitializedFile struct {
	Path      string
	Preserved bool
}

// Initialize creates private templates without replacing existing user files.
func Initialize(ctx context.Context, c Config, parallelChanged bool) ([]InitializedFile, error) {
	results := []InitializedFile{}
	values := record.MergeLayers(c.Values)
	delete(values, "inventory_configuration")
	if !parallelChanged && c.Environment["VXLAN_PARALLEL"] == "" {
		delete(values, "parallel")
	}
	body, e := yaml.Marshal(values)
	if e != nil {
		return results, e
	}
	for _, fileSpec := range []struct {
		path string
		body []byte
	}{{c.ConfigPath, body}, {c.EnvPath, []byte("# 设备凭据；可用 SSH key/agent\nNC_DEVICE_USERNAME=\nNC_DEVICE_PASSWORD=\n")}} {
		p, b := fileSpec.path, fileSpec.body
		if err := ctx.Err(); err != nil {
			return results, err
		}
		if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return results, e
		}
		file, err := os.CreateTemp(filepath.Dir(p), ".vxlan-init-*.tmp")
		if err != nil {
			return results, err
		}
		tmp := file.Name()
		err = file.Chmod(0600)
		if err == nil {
			_, err = file.Write(b)
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Link(tmp, p)
		}
		os.Remove(tmp)
		if os.IsExist(err) {
			results = append(results, InitializedFile{Path: p, Preserved: true})
			continue
		}
		if err != nil {
			return results, err
		}
		if err = report.SyncDirectory(filepath.Dir(p)); err != nil {
			return results, err
		}
		results = append(results, InitializedFile{Path: p})
	}
	return results, nil
}

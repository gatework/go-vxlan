package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

type Source struct {
	Path     string
	Body     []byte
	Document vxlan.Record
}

func ReadSources(ctx context.Context, batch string) ([]Source, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	paths, e := filepath.Glob(filepath.Join(batch, "evidence", "*.json"))
	if e != nil || len(paths) == 0 {
		return nil, fmt.Errorf("无设备报告")
	}
	sort.Strings(paths)
	sources := []Source{}
	hosts, names := map[string]bool{}, map[string]bool{}
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		body, e := os.ReadFile(p)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e != nil {
			return nil, e
		}
		doc, e := vxlan.DecodeDocument(body)
		if e != nil {
			return nil, fmt.Errorf("证据 JSON 无效")
		}
		if doc, e = vxlan.NewEvidenceDocument(doc); e != nil {
			return nil, e
		}
		device := record.Map(doc["device"])
		host, name := record.String(device["host"]), Basename(device)
		if hosts[host] || names[name] {
			return nil, fmt.Errorf("设备身份或输出名重复")
		}
		hosts[host], names[name] = true, true
		sources = append(sources, Source{p, body, doc})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return sources, nil
}

package workflow_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/workflow"
	"github.com/gatework/go-vxlan/report"
	"github.com/gatework/go-vxlan/vendors"
)

func TestCanceledCollectionRetainsAcceptedEvidence(t *testing.T) {
	profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := profile.Parse("configuration", "hostname leaf\n", true)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := vxlan.NewObservation("collection", "complete", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	device := vxlan.Record{"host": "192.0.2.1", "name": "leaf", "model": "N9K"}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := workflow.Collect(ctx, workflow.CollectionOptions{
		Directory: filepath.Join(t.TempDir(), "reports"), Workers: 1, Devices: []any{device}, Queries: profile,
		Collect: func(context.Context, vxlan.Record) (vxlan.Snapshot, error) {
			cancel() // A receipt was accepted just before the parent operation stopped.
			return vxlan.Snapshot{Target: device, Dimensions: map[string]vxlan.Observation{"configuration": configuration, "collection": collection}}, nil
		},
	})
	if result.State != workflow.CollectionInterrupted || result.Summary["completed"] != 1 || result.Summary["status"] != "interrupted" || result.Summary["report_error"] != nil {
		t.Fatalf("result: %+v", result)
	}
	sources, err := report.ReadSources(t.Context(), result.Directory)
	if err != nil || len(sources) != 1 {
		t.Fatalf("retained evidence: %d %v", len(sources), err)
	}
	if _, err = os.Stat(filepath.Join(result.Directory, "plan.json")); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledReviewDoesNotPublishSuccess(t *testing.T) {
	r, err := report.New(filepath.Join(t.TempDir(), "reports"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = workflow.Review(ctx, r, workflow.ReviewOptions{Standalone: true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(r.Directory, "summary.json")); !os.IsNotExist(err) {
		t.Fatalf("unexpected success artifact: %v", err)
	}
	if _, err = report.ReadSources(ctx, r.Directory); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = r.PublishJSON(ctx, "summary.json", vxlan.Record{"status": "complete"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCollectionFinalCallbacksKeepDurableAndReturnedStatusAligned(t *testing.T) {
	for _, mode := range []string{"published_cancel", "published_error", "delivery_cancel", "delivery_error"} {
		t.Run(mode, func(t *testing.T) {
			profile, err := vendors.NewBuiltinRegistry().Fetch("cisco_nxos", "")
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := profile.Parse("configuration", "hostname leaf\n", true)
			if err != nil {
				t.Fatal(err)
			}
			complete, err := vxlan.NewObservation("collection", "complete", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			device := vxlan.Record{"host": "192.0.2.1", "name": "leaf"}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			captures, deliveries := 0, 0
			result := workflow.Collect(ctx, workflow.CollectionOptions{
				Directory: filepath.Join(t.TempDir(), "reports"), Workers: 1, Devices: []any{device}, Queries: profile,
				Collect: func(context.Context, vxlan.Record) (vxlan.Snapshot, error) {
					captures++
					return vxlan.Snapshot{Target: device, Dimensions: map[string]vxlan.Observation{"configuration": configuration, "collection": complete}}, nil
				},
				Observe: func(event workflow.CollectionEvent) error {
					if event.Kind == workflow.CollectionPublished {
						if mode == "published_cancel" {
							cancel()
						}
						if mode == "published_error" {
							return errors.New("output unavailable")
						}
					}
					return nil
				},
				Deliver: func(vxlan.Record) error {
					deliveries++
					if mode == "delivery_cancel" {
						cancel()
					}
					if mode == "delivery_error" {
						return errors.New("output unavailable")
					}
					return nil
				},
			})
			wantStatus, wantState := "incomplete", workflow.CollectionFailed
			if ctx.Err() != nil {
				wantStatus, wantState = "interrupted", workflow.CollectionInterrupted
			}
			if result.State != wantState || result.Summary["status"] != wantStatus {
				t.Fatalf("result: %+v", result)
			}
			if captures != 1 || deliveries != 1 {
				t.Fatalf("replayed collection/delivery: %d/%d", captures, deliveries)
			}
			body, err := os.ReadFile(filepath.Join(result.Directory, "summary.json"))
			if err != nil {
				t.Fatal(err)
			}
			persisted, err := vxlan.DecodeDocument(body)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := vxlan.Fingerprint(result.Summary)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := vxlan.Fingerprint(persisted)
			if err != nil {
				t.Fatal(err)
			}
			if actual != expected {
				t.Fatalf("returned and retained summaries differ: %s", body)
			}
			sources, err := report.ReadSources(t.Context(), result.Directory)
			if err != nil || len(sources) != 1 {
				t.Fatalf("accepted evidence lost: %v", err)
			}
		})
	}
}

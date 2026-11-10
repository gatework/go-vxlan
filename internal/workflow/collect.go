package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gatework/go-netops/assess"
	"github.com/gatework/go-vxlan/fabric"
	"github.com/gatework/go-vxlan/rules"
	"path/filepath"
	"sync"
	"time"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/report"
)

type CollectionState uint8

const (
	CollectionUnknown CollectionState = iota
	CollectionComplete
	CollectionPartial
	CollectionFailed
	CollectionInterrupted
)

type CollectionEventKind uint8

const (
	CollectionStarted CollectionEventKind = iota + 1
	CollectionProgress
	CollectionPublished
)

type CollectionEvent struct {
	Kind                    CollectionEventKind
	Current, Total, Workers int
	Device                  vxlan.Record
	Status, Path            string
}
type CollectionOptions struct {
	Devices              []any
	Directory            string
	Workers              int
	Policy               vxlan.Record
	Queries              Queries
	Scripts, Verbose     bool
	InitialOutputFailure bool
	Collect              func(context.Context, vxlan.Record) (vxlan.Snapshot, error)
	Observe              func(CollectionEvent) error
	Deliver              func(vxlan.Record) error
}
type CollectionResult struct {
	State     CollectionState
	Summary   vxlan.Record
	Directory string
	Err       error
}

// Collect owns a batch until every admitted device and publication has finished.
// Output failures are incorporated in the retained report without replaying capture.
func Collect(ctx context.Context, o CollectionOptions) CollectionResult {
	if o.Collect == nil || o.Workers < 1 {
		return CollectionResult{State: CollectionFailed, Err: fmt.Errorf("invalid collection request")}
	}
	outputFailed := o.InitialOutputFailure
	notice := func(event CollectionEvent) {
		if o.Observe != nil {
			if err := o.Observe(event); err != nil {
				outputFailed = true
			}
		}
	}
	names := map[string]bool{}
	for _, d := range o.Devices {
		n := report.Basename(record.Map(d))
		if names[n] {
			return CollectionResult{State: CollectionFailed, Err: fmt.Errorf("设备报告名称冲突")}
		}
		names[n] = true
	}
	r, e := report.New(o.Directory)
	if e != nil {
		return CollectionResult{State: CollectionFailed, Err: e}
	}
	notice(CollectionEvent{Kind: CollectionStarted, Total: len(o.Devices), Workers: o.Workers})
	type outcome struct {
		result   vxlan.Record
		snapshot *vxlan.Snapshot
	}
	jobs := make(chan vxlan.Record)
	out := make(chan outcome, o.Workers)
	var wg sync.WaitGroup
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for device := range jobs {
				if ctx.Err() != nil {
					return
				}
				func() {
					started := time.Now()
					result := vxlan.Record{"device": device, "status": "failed", "dimensions": vxlan.Record{}, "report_saved": false}
					var snapshot *vxlan.Snapshot
					defer func() {
						if recover() != nil {
							result["error"] = "collection_failed"
						}
						result["duration_ms"] = (time.Since(started) + 500*time.Microsecond) / time.Millisecond
						out <- outcome{result, snapshot}
					}()
					s, err := o.Collect(ctx, device)
					if err != nil {
						result["error"] = "collection_failed"
						return
					}
					snapshot = &s
					result["status"] = s.Dimensions["collection"].Status
					dims := vxlan.Record{}
					for name, o := range s.Dimensions {
						codes := []string{}
						seen := map[string]bool{}
						for _, issue := range o.Issues {
							code := record.String(issue["code"])
							if !seen[code] {
								codes = append(codes, code)
								seen[code] = true
							}
						}
						dims[name] = vxlan.Record{"status": o.Status, "records": len(o.Records), "issues": codes}
					}
					result["dimensions"] = dims
				}()
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, d := range o.Devices {
			select {
			case jobs <- record.Map(d):
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(out) }()
	// Accepted evidence must be retained even when admission or device I/O is canceled.
	finalizeCtx := context.WithoutCancel(ctx)
	results := []vxlan.Record{}
	failures := vxlan.Record{}
	scripts := o.Scripts
	for item := range out {
		res := item.result
		body := record.MergeLayers(res, vxlan.Record{"snapshot": item.snapshot})
		delete(body, "report_saved")
		doc, err := vxlan.NewEvidenceDocument(body)
		if err == nil {
			doc["assessment"], err = deviceAssessment(finalizeCtx, doc, o.Queries)
		}
		if err == nil {
			err = r.PublishCollectionDevice(finalizeCtx, doc, res)
		}
		if err != nil {
			failures["report_error"] = "device_report_failed"
		} else {
			res["report_saved"] = true
		}

		results = append(results, res)
		if o.Verbose || len(results)%25 == 0 || len(results) == len(o.Devices) {
			notice(CollectionEvent{Kind: CollectionProgress, Current: len(results), Total: len(o.Devices), Device: record.Map(res["device"]), Status: record.String(res["status"])})
		}
	}
	if len(results) > 0 {
		sources, err := report.ReadSources(finalizeCtx, r.Directory)
		if err == nil {
			review, err := Review(finalizeCtx, r, ReviewOptions{Sources: sources, Policy: o.Policy, Queries: o.Queries, Scripts: scripts})
			if err != nil {
				failures["report_error"] = "review_report_failed"
			} else {
				r.Review = review
			}
		} else {
			failures["report_error"] = "review_evidence_failed"
		}
	}

	// Publication callbacks can themselves fail or cancel the batch. Keep the
	// returned summary and its durable artifact synchronized after each boundary.
	var summary vxlan.Record
	finalizedInterrupted, finalizedOutputFailure := false, false
	persist := func() error {
		finalizedInterrupted, finalizedOutputFailure = ctx.Err() != nil, outputFailed
		if outputFailed {
			failures["output_error"] = vxlan.Record{"error_type": "write_failed"}
		}
		var err error
		summary, err = r.Finish(finalizeCtx, results, o.Devices, finalizedInterrupted, failures)
		return err
	}
	failedPublication := func(err error) CollectionResult {
		state := CollectionFailed
		if ctx.Err() != nil {
			state = CollectionInterrupted
		}
		return CollectionResult{State: state, Summary: summary, Directory: r.Directory, Err: err}
	}
	refresh := func() error {
		if (ctx.Err() != nil) != finalizedInterrupted || outputFailed != finalizedOutputFailure {
			return persist()
		}
		return nil
	}
	if err := persist(); err != nil {
		return failedPublication(err)
	}
	notice(CollectionEvent{Kind: CollectionPublished, Path: filepath.Join(r.Directory, "summary.txt")})
	if err := refresh(); err != nil {
		return failedPublication(err)
	}
	if o.Deliver != nil {
		if err := o.Deliver(summary); err != nil {
			outputFailed = true
		}
	}
	if err := refresh(); err != nil {
		return failedPublication(err)
	}
	if ctx.Err() != nil {
		return CollectionResult{State: CollectionInterrupted, Summary: summary, Directory: r.Directory}
	}
	if len(failures) > 0 {
		return CollectionResult{State: CollectionFailed, Summary: summary, Directory: r.Directory}
	}
	if summary["status"] == "complete" {
		return CollectionResult{State: CollectionComplete, Summary: summary, Directory: r.Directory}
	}
	return CollectionResult{State: CollectionPartial, Summary: summary, Directory: r.Directory}
}

// deviceAssessment runs the per-device rules on one collected document and
// returns the result as a JSON value for the evidence document.
func deviceAssessment(ctx context.Context, doc vxlan.Record, queries Queries) (any, error) {
	device, err := fabric.EncodeDocument(doc)
	if err != nil {
		return nil, err
	}
	model, err := fabric.Build([]*fabric.Device{device}, nil)
	if err != nil {
		return nil, err
	}
	var commands rules.Commands
	if queries != nil {
		commands = queries
	}
	assessor, err := rules.NewAssessor(assess.Policy{}, commands)
	if err != nil {
		return nil, err
	}
	r, err := assessor.Assess(ctx, model)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(r.Devices[0])
	if err != nil {
		return nil, err
	}
	return vxlan.DecodeDocument(body)
}

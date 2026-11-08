package collect

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
	"github.com/gatework/go-vxlan/parser"
)

// Capture is an explicit transport receipt; its body is never printed implicitly.
// Complete means the command was accepted and its body was verified. A later
// execution error may accompany a complete capture without invalidating its body.
type Capture struct {
	Body                   string
	Complete               bool
	Evidence               []vxlan.Record
	StartedAt, CompletedAt *time.Time
}

func (c Capture) String() string {
	return fmt.Sprintf("Capture{complete=%t bytes=%d}", c.Complete, len(c.Body))
}
func (c Capture) GoString() string { return c.String() }

type Session interface {
	Read(context.Context, string) (Capture, error)
}

// OpenSession lends one exclusive session to a synchronous, single callback.
// The callback context includes session cancellation and must govern nested work.
type OpenSession func(context.Context, func(context.Context, Session) error) error

var errSessionReentered = errors.New("session reentered")

type Request struct {
	Target     vxlan.Record
	FabricKey  any
	Dimensions []string
	Profile    *parser.Profile
}

func (r Request) String() string   { return fmt.Sprintf("Request{dimensions=%d}", len(r.Dimensions)) }
func (r Request) GoString() string { return r.String() }
func request(r Request) (Request, error) {
	if _, err := vxlan.ProjectRecord(vxlan.Record{"target": r.Target, "fabric_key": r.FabricKey}); err != nil {
		return Request{}, err
	}
	if r.Target == nil {
		return r, fmt.Errorf("target is required")
	}
	if r.Profile == nil {
		return r, fmt.Errorf("parser profile is required")
	}
	if r.Dimensions == nil {
		r.Dimensions = r.Profile.Dimensions()
	}
	if len(r.Dimensions) == 0 {
		return r, fmt.Errorf("empty dimensions")
	}
	seen := map[string]bool{}
	commands := r.Profile.Commands()
	for _, n := range r.Dimensions {
		if seen[n] || commands[n] == "" {
			return r, fmt.Errorf("unknown or duplicate dimension")
		}
		seen[n] = true
	}
	r.Target = record.Copy(r.Target).(vxlan.Record)
	r.FabricKey = record.Copy(r.FabricKey)
	r.Dimensions = append([]string{}, r.Dimensions...)
	return r, nil
}
func failure(name, code string, details vxlan.Record) vxlan.Observation {
	r := vxlan.Record{"code": code}
	for k, v := range details {
		r[k] = v
	}
	o := observation(name, "failed", nil, []vxlan.Record{r})
	now := time.Now().UTC()
	o.CompletedAt = &now
	return o
}
func collectSnapshot(r Request, dimensions map[string]vxlan.Observation) vxlan.Snapshot {
	if _, ok := dimensions["collection"]; !ok {
		dimensions["collection"] = collectionObservation(dimensions, nil, nil)
	}
	now := time.Now().UTC()
	return vxlan.Snapshot{Target: r.Target, FabricKey: r.FabricKey, Dimensions: dimensions, ObservedAt: &now}
}

func collectionObservation(dimensions map[string]vxlan.Observation, issues, evidence []vxlan.Record) vxlan.Observation {
	status, some := "complete", false
	for name, o := range dimensions {
		if name == "collection" {
			continue
		}
		if o.Status == "complete" || o.Status == "partial" {
			some = true
		}
		if !o.Complete() {
			status = "partial"
		}
	}
	if len(issues) > 0 {
		status = "partial"
	}
	if !some {
		status = "failed"
	}
	for _, issue := range issues {
		if issue["code"] == "session_close_failed" || issue["code"] == "session_reentered" {
			status = "failed"
		}
	}
	o := observation("collection", status, nil, issues)
	o.Evidence = record.CopyRecords(evidence)
	o.CompletedAt = new(time.Now().UTC())
	return o
}

// Collect owns only the callback protocol; the opener retains transport lifecycle ownership.
func Collect(ctx context.Context, open OpenSession, r Request) (vxlan.Snapshot, error) {
	r, e := request(r)
	if e != nil {
		return vxlan.Snapshot{}, e
	}
	if open == nil {
		return vxlan.Snapshot{}, fmt.Errorf("nil opener")
	}
	obs := map[string]vxlan.Observation{}
	started, finished := false, false
	e = open(ctx, func(ctx context.Context, session Session) error {
		if started {
			for _, n := range r.Dimensions {
				if _, ok := obs[n]; !ok {
					obs[n] = failure(n, "session_reentered", nil)
				}
			}
			addCollectionIssues(obs, []string{"session_reentered"}, nil)
			return errSessionReentered
		}
		started = true
		obs = readDimensions(ctx, session, r)
		finished = true
		return nil
	})
	if e != nil {
		fallback := "connection_failed"
		if finished {
			fallback = "session_close_failed"
		}
		codes := collectionErrorCodes(e, fallback)
		for _, n := range r.Dimensions {
			if _, ok := obs[n]; !ok {
				obs[n] = failure(n, codes[0], nil)
			}
		}
		addCollectionIssues(obs, codes, nil)
	}
	if !finished && obs["collection"].Name == "" {
		for _, n := range r.Dimensions {
			obs[n] = failure(n, "session_not_opened", nil)
		}
		obs["collection"] = failure("collection", "session_not_opened", nil)
	}
	return collectSnapshot(r, obs), nil
}

// CollectSession borrows an already-open, exclusively held session without reconnecting it.
func CollectSession(ctx context.Context, session Session, r Request) (vxlan.Snapshot, error) {
	r, e := request(r)
	if e != nil {
		return vxlan.Snapshot{}, e
	}
	return collectSnapshot(r, readDimensions(ctx, session, r)), nil
}

// CodedError supplies a safe diagnostic code. Errors with independent causes
// may also implement FailureCodes() []string to preserve each classification.
type CodedError interface {
	error
	FailureCode() string
}

func collectionError(e error) string {
	if errors.Is(e, context.Canceled) {
		return "interrupted"
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(e, errSessionReentered) {
		return "session_reentered"
	}
	if coded, ok := errors.AsType[CodedError](e); ok {
		return coded.FailureCode()
	}
	return "connection_failed"
}

// A classified error is one diagnostic cause unless it supplies FailureCodes.
// Ordinary wrappers and joins may contain independent operation/cleanup causes.
func collectionErrorCodes(err error, fallback string) []string {
	var codes []string
	seen := map[string]bool{}
	add := func(code string) {
		if code == "" {
			code = fallback
		}
		if !seen[code] {
			seen[code] = true
			codes = append(codes, code)
		}
	}
	var visit func(error)
	visit = func(err error) {
		if err == nil {
			return
		}
		if multiple, ok := err.(interface{ FailureCodes() []string }); ok {
			if classified := multiple.FailureCodes(); len(classified) > 0 {
				for _, code := range classified {
					add(code)
				}
				return
			}
		}
		code := ""
		if coded, ok := err.(CodedError); ok {
			code = coded.FailureCode()
			if code != "session_close_failed" {
				code = collectionError(err)
			}
		} else {
			switch wrapped := err.(type) {
			case interface{ Unwrap() []error }:
				for _, cause := range wrapped.Unwrap() {
					visit(cause)
				}
				return
			case interface{ Unwrap() error }:
				if cause := wrapped.Unwrap(); cause != nil {
					visit(cause)
					return
				}
			}
			code = collectionError(err)
			if code == "connection_failed" {
				code = fallback
			}
		}
		add(code)
	}
	visit(err)
	if len(codes) == 0 {
		return []string{fallback}
	}
	return codes
}

func addCollectionIssues(obs map[string]vxlan.Observation, codes []string, details vxlan.Record) {
	o := obs["collection"]
	seen := map[string]bool{}
	for _, issue := range o.Issues {
		code, _ := issue["code"].(string)
		seen[code] = true
	}
	for _, code := range codes {
		if seen[code] {
			continue
		}
		issue := vxlan.Record{"code": code}
		for key, value := range details {
			issue[key] = value
		}
		o.Issues = append(o.Issues, issue)
		seen[code] = true
	}
	obs["collection"] = collectionObservation(obs, o.Issues, o.Evidence)
}

func readDimensions(ctx context.Context, session Session, r Request) map[string]vxlan.Observation {
	obs := map[string]vxlan.Observation{}
	failed := ""
	read := func(command string) (Capture, error) {
		if failed != "" {
			return Capture{}, fmt.Errorf("prior failure")
		}
		if e := ctx.Err(); e != nil {
			failed = collectionError(e)
			return Capture{}, e
		}
		if session == nil {
			failed = "session_not_opened"
			return Capture{}, fmt.Errorf("missing session")
		}
		c, e := session.Read(ctx, command)
		if _, evidenceErr := vxlan.ProjectRecord(vxlan.Record{"evidence": c.Evidence, "started_at": c.StartedAt, "completed_at": c.CompletedAt}); evidenceErr != nil {
			// Invalid metadata cannot be copied or persisted. Accepted body facts
			// still survive independently, accompanied by the evidence failure.
			c.Evidence, c.StartedAt, c.CompletedAt = nil, nil, nil
			e = errors.Join(e, evidenceErr)
		}
		if e != nil {
			if state, ok := session.(interface{ Connected() bool }); ctx.Err() != nil || !ok || !state.Connected() {
				failed = collectionError(e)
			}
		} else if !c.Complete {
			failed = "incomplete_output"
			e = fmt.Errorf("incomplete capture")
		}
		return c, e
	}
	for _, cmd := range r.Profile.PreparationCommands() {
		c, e := read(cmd)
		o := obs["collection"]
		o.Evidence = append(o.Evidence, record.CopyRecords(c.Evidence)...)
		obs["collection"] = o
		if e != nil {
			if failed == "" {
				failed = collectionError(e)
			}
			for _, n := range r.Dimensions {
				obs[n] = failure(n, failed, nil)
			}
			addCollectionIssues(obs, collectionErrorCodes(e, failed), vxlan.Record{"command": cmd})
			return obs
		}
	}
	ordered := []string{}
	for _, n := range r.Dimensions {
		if n == "configuration" {
			ordered = append(ordered, n)
		}
	}
	for _, n := range r.Dimensions {
		if n != "configuration" {
			ordered = append(ordered, n)
		}
	}
	for _, name := range ordered {
		if reason := r.Profile.AbsentReason(name, obs["configuration"], true); failed == "" && reason != "" {
			obs[name] = observation(name, "complete", nil, []vxlan.Record{{"code": reason}})
			continue
		}
		cmd := r.Profile.Command(name)
		skipped := failed != ""
		started := time.Now().UTC()
		c, e := read(cmd)
		ended := time.Now().UTC()
		var o vxlan.Observation
		if e != nil && !skipped {
			fallback := failed
			if fallback == "" {
				fallback = "connection_failed"
			}
			addCollectionIssues(obs, collectionErrorCodes(e, fallback), vxlan.Record{"command": cmd})
		}
		if !c.Complete {
			code := failed
			if code == "" {
				code = collectionError(e)
			}
			o = failure(name, code, vxlan.Record{"command": cmd, "skipped": skipped})
		} else if reason := r.Profile.AbsentReason(name, obs["configuration"], false); strings.TrimSpace(c.Body) == "" && reason != "" {
			o = observation(name, "complete", nil, []vxlan.Record{{"code": reason}})
		} else {
			var parseErr error
			o, parseErr = r.Profile.Parse(name, c.Body, true)
			if parseErr != nil {
				o = failure(name, "command_processing_failed", vxlan.Record{"command": cmd})
			}
		}
		o.StartedAt = &started
		o.CompletedAt = &ended
		if c.StartedAt != nil {
			o.StartedAt = new(*c.StartedAt)
		}
		if c.CompletedAt != nil {
			o.CompletedAt = new(*c.CompletedAt)
		}
		o.Evidence = record.CopyRecords(c.Evidence)
		if c.Complete && len(o.Evidence) == 0 {
			o.Evidence = []vxlan.Record{{"command": cmd, "sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(c.Body))), "bytes": len(c.Body), "observed_at": ended.Format("2006-01-02T15:04:05.000000Z")}}
		}
		obs[name] = o
	}
	collection := obs["collection"]
	obs["collection"] = collectionObservation(obs, collection.Issues, collection.Evidence)
	return obs
}

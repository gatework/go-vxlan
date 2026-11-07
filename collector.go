package vxlan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Capture is an explicit transport receipt; its body is never printed implicitly.
// Complete means the command was accepted and its body was verified. A later
// execution error may accompany a complete capture without invalidating its body.
type Capture struct {
	Body                   string
	Complete               bool
	Evidence               []Record
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
	Target          Record
	FabricKey       any
	Platform, Model string
	Dimensions      []string
	Registry        *ParserRegistry
	profile         *Profile
}

func (r Request) String() string   { return fmt.Sprintf("Request{dimensions=%d}", len(r.Dimensions)) }
func (r Request) GoString() string { return r.String() }
func request(r Request) (Request, error) {
	if r.Target == nil {
		return r, fmt.Errorf("target is required")
	}
	if r.Platform == "" {
		r.Platform = "cisco_nxos"
	}
	if r.Registry == nil {
		r.Registry = DefaultParserRegistry()
	}
	var err error
	r.profile, err = r.Registry.Fetch(r.Platform, r.Model)
	if err != nil {
		return r, err
	}
	if r.Dimensions == nil {
		r.Dimensions = DimensionNames()
	}
	if len(r.Dimensions) == 0 {
		return r, fmt.Errorf("empty dimensions")
	}
	seen := map[string]bool{}
	commands := r.profile.Commands()
	for _, n := range r.Dimensions {
		if seen[n] || commands[n] == "" {
			return r, fmt.Errorf("unknown or duplicate dimension")
		}
		seen[n] = true
	}
	r.Target = clone(r.Target).(Record)
	r.FabricKey = clone(r.FabricKey)
	r.Dimensions = append([]string{}, r.Dimensions...)
	return r, nil
}
func failure(name, code string, details Record) Observation {
	r := Record{"code": code}
	for k, v := range details {
		r[k] = v
	}
	o := observation(name, "failed", nil, []Record{r})
	now := time.Now().UTC()
	o.CompletedAt = &now
	return o
}
func collectSnapshot(r Request, dimensions map[string]Observation) Snapshot {
	if _, ok := dimensions["collection"]; !ok {
		dimensions["collection"] = collectionObservation(dimensions, nil, nil)
	}
	now := time.Now().UTC()
	return Snapshot{Target: r.Target, FabricKey: r.FabricKey, Dimensions: dimensions, ObservedAt: &now}
}

func collectionObservation(dimensions map[string]Observation, issues, evidence []Record) Observation {
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
	o.Evidence = copyRecords(evidence)
	o.CompletedAt = new(time.Now().UTC())
	return o
}

// Collect owns only the callback protocol; the opener retains transport lifecycle ownership.
func Collect(ctx context.Context, open OpenSession, r Request) (Snapshot, error) {
	r, e := request(r)
	if e != nil {
		return Snapshot{}, e
	}
	if open == nil {
		return Snapshot{}, fmt.Errorf("nil opener")
	}
	obs := map[string]Observation{}
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
func CollectSession(ctx context.Context, session Session, r Request) (Snapshot, error) {
	r, e := request(r)
	if e != nil {
		return Snapshot{}, e
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

func addCollectionIssues(obs map[string]Observation, codes []string, details Record) {
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
		issue := Record{"code": code}
		for key, value := range details {
			issue[key] = value
		}
		o.Issues = append(o.Issues, issue)
		seen[code] = true
	}
	obs["collection"] = collectionObservation(obs, o.Issues, o.Evidence)
}

func readDimensions(ctx context.Context, session Session, r Request) map[string]Observation {
	obs := map[string]Observation{}
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
	for _, cmd := range []string{"terminal length 0", "terminal width 511"} {
		c, e := read(cmd)
		o := obs["collection"]
		o.Evidence = append(o.Evidence, copyRecords(c.Evidence)...)
		obs["collection"] = o
		if e != nil {
			if failed == "" {
				failed = collectionError(e)
			}
			for _, n := range r.Dimensions {
				obs[n] = failure(n, failed, nil)
			}
			addCollectionIssues(obs, collectionErrorCodes(e, failed), Record{"command": cmd})
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
		if name == "vpc" && failed == "" && unconfigured(name, obs["configuration"]) {
			obs[name] = observation(name, "complete", nil, []Record{{"code": "vpc_not_configured"}})
			continue
		}
		cmd := r.profile.Command(name)
		skipped := failed != ""
		started := time.Now().UTC()
		c, e := read(cmd)
		ended := time.Now().UTC()
		var o Observation
		if e != nil && !skipped {
			fallback := failed
			if fallback == "" {
				fallback = "connection_failed"
			}
			addCollectionIssues(obs, collectionErrorCodes(e, fallback), Record{"command": cmd})
		}
		if !c.Complete {
			code := failed
			if code == "" {
				code = collectionError(e)
			}
			o = failure(name, code, Record{"command": cmd, "skipped": skipped})
		} else if strings.TrimSpace(c.Body) == "" && unconfigured(name, obs["configuration"]) {
			code := "nve_not_configured"
			if name == "port_channels" {
				code = "port_channels_not_configured"
			}
			o = observation(name, "complete", nil, []Record{{"code": code}})
		} else {
			var parseErr error
			o, parseErr = r.profile.Parse(name, c.Body, true)
			if parseErr != nil {
				o = failure(name, "command_processing_failed", Record{"command": cmd})
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
		o.Evidence = copyRecords(c.Evidence)
		if c.Complete && len(o.Evidence) == 0 {
			o.Evidence = []Record{{"command": cmd, "sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(c.Body))), "bytes": len(c.Body), "observed_at": ended.Format("2006-01-02T15:04:05.000000Z")}}
		}
		obs[name] = o
	}
	collection := obs["collection"]
	obs["collection"] = collectionObservation(obs, collection.Issues, collection.Evidence)
	return obs
}
func unconfigured(name string, o Observation) bool {
	if !o.Complete() || len(o.Records) != 1 {
		return false
	}
	d := o.Records[0]
	switch name {
	case "vpc":
		if d["vpc_domain"] != nil {
			return false
		}
		for _, v := range cfgStrings(d["features"]) {
			if v == "vpc" {
				return false
			}
		}
		return true
	case "nve_peers", "nve_vnis":
		return cfgMap(d["nve"])["interface"] == nil
	case "port_channels":
		for n, v := range cfgMap(d["interfaces"]) {
			if cfgMatch(`(?i)port-channel\d+`, n) != nil || cfgMap(v)["channel_group"] != nil {
				return false
			}
		}
		return true
	}
	return false
}

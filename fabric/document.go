package fabric

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gatework/go-netops/evidence"
)

// ErrDocument reports a device report that lacks identity or dimensions.
var ErrDocument = errors.New("fabric: invalid device document")

type documentShape struct {
	Device   Identity `json:"device"`
	Snapshot struct {
		Dimensions map[evidence.Dimension]struct {
			Status  evidence.Status   `json:"status"`
			Records []json.RawMessage `json:"records"`
			Issues  []json.RawMessage `json:"issues"`
		} `json:"dimensions"`
	} `json:"snapshot"`
}

// DecodeDocument builds a device from a collected device report: an object
// with "device" identity and "snapshot.dimensions" observations. Identity
// fields other than host, name and model are ignored.
func DecodeDocument(body []byte) (*Device, error) {
	var doc documentShape
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	if doc.Device.Host == "" {
		return nil, fmt.Errorf("%w: missing device host", ErrDocument)
	}
	dims := map[evidence.Dimension]Observed{}
	for name, o := range doc.Snapshot.Dimensions {
		if !o.Status.Valid() {
			return nil, fmt.Errorf("%w: dimension %s status", ErrDocument, name)
		}
		dims[name] = Observed{Status: o.Status, Records: o.Records, Issues: o.Issues}
	}
	return NewDevice(doc.Device, dims), nil
}

// EncodeDocument is the inverse of DecodeDocument for a generic document
// value, such as the legacy review's decoded report.
func EncodeDocument(document any) (*Device, error) {
	body, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	return DecodeDocument(body)
}

// DecodeConfiguration strictly decodes one configuration record. Unknown
// fields are an error: unmodeled facts must not authorize a change.
func DecodeConfiguration(body []byte) (*Configuration, error) {
	var c Configuration
	if err := strict(body, &c); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	return &c, nil
}

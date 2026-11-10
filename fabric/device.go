package fabric

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/go-netops/evidence"
)

// Dimensions collected per device, in collection order.
const (
	DimConfiguration evidence.Dimension = "configuration"
	DimCDP           evidence.Dimension = "cdp_neighbors"
	DimNVEPeers      evidence.Dimension = "nve_peers"
	DimNVEVNIs       evidence.Dimension = "nve_vnis"
	DimBGP           evidence.Dimension = "bgp_neighbors"
	DimOSPF          evidence.Dimension = "ospf_neighbors"
	DimVPC           evidence.Dimension = "vpc"
	DimInterfaces    evidence.Dimension = "interfaces"
	DimPortChannels  evidence.Dimension = "port_channels"
	DimMACs          evidence.Dimension = "mac_addresses"
	DimL2RouteMACs   evidence.Dimension = "l2route_macs"
	DimL2RouteMACIPs evidence.Dimension = "l2route_mac_ips"
)

// Dimensions lists every device dimension in collection order.
func Dimensions() []evidence.Dimension {
	return []evidence.Dimension{DimConfiguration, DimCDP, DimNVEPeers, DimNVEVNIs, DimBGP, DimOSPF, DimVPC,
		DimInterfaces, DimPortChannels, DimMACs, DimL2RouteMACs, DimL2RouteMACIPs}
}

// IssueUnmodeled marks a record containing a field the model does not know.
// The dimension becomes partial, so rules that need it do not run.
const IssueUnmodeled = "unmodeled_fact"

// Role is a device's fabric role.
type Role string

const (
	RoleLeaf       Role = "leaf"
	RoleBorder     Role = "border"
	RoleSpine      Role = "spine"
	RoleUnassigned Role = ""
)

// Identity is how the inventory knows a device.
type Identity struct {
	Host  string `json:"host"`
	Name  string `json:"name,omitempty"`
	Model string `json:"model,omitempty"`
}

// Device is one device's typed evidence.
type Device struct {
	Identity
	Role          Role                                    `json:"role,omitempty"`
	Configuration *Configuration                          `json:"configuration,omitempty"`
	NVEPeers      []NVEPeer                               `json:"nve_peers,omitempty"`
	NVEVNIs       []NVEVNI                                `json:"nve_vnis,omitempty"`
	BGPNeighbors  []BGPNeighbor                           `json:"bgp_neighbors,omitempty"`
	OSPFNeighbors []OSPFNeighbor                          `json:"ospf_neighbors,omitempty"`
	CDPNeighbors  []CDPNeighbor                           `json:"cdp_neighbors,omitempty"`
	VPC           *VPC                                    `json:"vpc,omitempty"`
	Interfaces    []InterfaceStatus                       `json:"interfaces,omitempty"`
	PortChannels  []PortChannel                           `json:"port_channels,omitempty"`
	MACs          []MACEntry                              `json:"mac_addresses,omitempty"`
	L2RouteMACs   []L2RouteMAC                            `json:"l2route_macs,omitempty"`
	L2RouteMACIPs []L2RouteMACIP                          `json:"l2route_mac_ips,omitempty"`
	Coverage      evidence.Coverage                       `json:"coverage"`
	Issues        map[evidence.Dimension][]evidence.Issue `json:"issues,omitempty"`
}

// Has reports whether a dimension is complete for this device.
func (d *Device) Has(dim evidence.Dimension) bool { return d.Coverage.Status(dim).Complete() }

// Observed is the parser output for one dimension, independent of the
// legacy record representation: a status, records as JSON objects and
// issues as JSON objects.
type Observed struct {
	Status  evidence.Status
	Records []json.RawMessage
	Issues  []json.RawMessage
}

// NewDevice decodes observed dimensions into a typed device. Unknown
// dimensions are ignored; a record that does not fit the model downgrades
// its dimension to partial with an unmodeled_fact issue instead of failing.
func NewDevice(id Identity, dims map[evidence.Dimension]Observed) *Device {
	d := &Device{Identity: id, Coverage: evidence.Coverage{}, Issues: map[evidence.Dimension][]evidence.Issue{}}
	for _, dim := range Dimensions() {
		o, ok := dims[dim]
		if !ok {
			continue
		}
		status := o.Status
		issues := make([]evidence.Issue, 0, len(o.Issues))
		for _, raw := range o.Issues {
			issue, err := DecodeIssue(raw)
			if err != nil {
				issue = evidence.Issue{Code: IssueUnmodeled}
			}
			issues = append(issues, issue)
		}
		if err := d.decode(dim, o.Records); err != nil {
			issues = append(issues, evidence.Issue{Code: IssueUnmodeled, Detail: err.Error()})
		}
		if slices.ContainsFunc(issues, func(i evidence.Issue) bool { return i.Code == IssueUnmodeled }) && status == evidence.StatusComplete {
			status = evidence.StatusPartial
		}
		d.Coverage[dim] = status
		if len(issues) > 0 {
			d.Issues[dim] = issues
		}
	}
	return d
}

func (d *Device) decode(dim evidence.Dimension, records []json.RawMessage) error {
	switch dim {
	case DimConfiguration:
		switch len(records) {
		case 0:
			return nil
		case 1:
			var c Configuration
			if err := strict(records[0], &c); err != nil {
				return err
			}
			d.Configuration = &c
			return nil
		}
		return fmt.Errorf("configuration has %d records", len(records))
	case DimVPC:
		switch len(records) {
		case 0:
			return nil
		case 1:
			var v VPC
			if err := strict(records[0], &v); err != nil {
				return err
			}
			d.VPC = &v
			return nil
		}
		return fmt.Errorf("vpc has %d records", len(records))
	case DimCDP:
		return rows(records, &d.CDPNeighbors)
	case DimNVEPeers:
		return rows(records, &d.NVEPeers)
	case DimNVEVNIs:
		return rows(records, &d.NVEVNIs)
	case DimBGP:
		return rows(records, &d.BGPNeighbors)
	case DimOSPF:
		return rows(records, &d.OSPFNeighbors)
	case DimInterfaces:
		return rows(records, &d.Interfaces)
	case DimPortChannels:
		return rows(records, &d.PortChannels)
	case DimMACs:
		return rows(records, &d.MACs)
	case DimL2RouteMACs:
		return rows(records, &d.L2RouteMACs)
	case DimL2RouteMACIPs:
		return rows(records, &d.L2RouteMACIPs)
	}
	return nil
}

func rows[T any](records []json.RawMessage, dst *[]T) error {
	out := make([]T, 0, len(records))
	for i, raw := range records {
		var v T
		if err := strict(raw, &v); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		out = append(out, v)
	}
	*dst = out
	return nil
}

func strict(raw json.RawMessage, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("unmodeled field: %w", err)
	}
	return nil
}

// DecodeIssue converts a parser issue object to evidence.Issue. Known
// accounting fields map to typed fields, identity fields to Scope.
func DecodeIssue(raw json.RawMessage) (evidence.Issue, error) {
	var fields map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&fields); err != nil {
		return evidence.Issue{}, err
	}
	var issue evidence.Issue
	intOf := func(v any) (int, bool) {
		n, ok := v.(json.Number)
		if !ok {
			return 0, false
		}
		i, err := strconv.Atoi(n.String())
		return i, err == nil
	}
	for k, v := range fields {
		switch k {
		case "code":
			s, ok := v.(string)
			if !ok || s == "" {
				return evidence.Issue{}, fmt.Errorf("issue code")
			}
			issue.Code = s
		case "line", "first_line":
			n, ok := intOf(v)
			if !ok {
				return evidence.Issue{}, fmt.Errorf("issue %s", k)
			}
			issue.Line = n
		case "count":
			n, ok := intOf(v)
			if !ok {
				return evidence.Issue{}, fmt.Errorf("issue count")
			}
			issue.Count = n
		case "expected", "observed", "parsed":
			n, ok := intOf(v)
			if !ok {
				// Device-declared totals can exceed int; keep the exact digits.
				digits, isNumber := v.(json.Number)
				if !isNumber {
					return evidence.Issue{}, fmt.Errorf("issue %s", k)
				}
				issue.Detail = strings.TrimSpace(issue.Detail + " " + k + "=" + digits.String())
				continue
			}
			if k == "expected" {
				issue.Expected = &n
			} else {
				issue.Observed = &n
			}
		case "field":
			s, _ := v.(string)
			issue.Fields = append(issue.Fields, s)
		case "fields":
			list, ok := v.([]any)
			if !ok {
				return evidence.Issue{}, fmt.Errorf("issue fields")
			}
			for _, e := range list {
				s, _ := e.(string)
				issue.Fields = append(issue.Fields, s)
			}
		default:
			s, ok := v.(string)
			if !ok {
				return evidence.Issue{}, fmt.Errorf("issue field %s", k)
			}
			if issue.Scope == nil {
				issue.Scope = map[string]string{}
			}
			issue.Scope[k] = s
		}
	}
	if issue.Code == "" {
		return evidence.Issue{}, fmt.Errorf("issue code")
	}
	return issue, nil
}

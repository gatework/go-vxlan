package review

import (
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

func Advice(doc vxlan.Record, queries QueryCatalog, scripts bool, additions []vxlan.Record) (vxlan.Record, error) {
	advice, err := vxlan.ProjectRecord(CombineRecommendations(Recommendations(doc, queries), additions))
	if err != nil {
		return nil, err
	}
	if !scripts {
		for _, x := range record.List(advice["items"]) {
			m := record.Map(x)
			delete(m, "change")
			delete(m, "template")
			m["commands"] = []string{}
			m["rollback"] = []string{}
		}
	}
	return advice, nil
}

// QueryCatalog supplies collection and review-only verification commands from
// the selected parser profile. Review never executes commands or owns a session.
type QueryCatalog interface {
	Command(string) string
	VerificationCommands(scope string) []string
}

func queryCommand(queries QueryCatalog, dimension string) string {
	if queries == nil {
		return ""
	}
	return queries.Command(dimension)
}

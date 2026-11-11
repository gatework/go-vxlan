package vendors

import (
	"github.com/gatework/go-vxlan/parser"
	"github.com/gatework/go-vxlan/vendors/nxos"
)

// NewBuiltinRegistry constructs the immutable built-in NX-OS parsing profile registry.
func NewBuiltinRegistry() *parser.Registry {
	r, e := parser.NewRegistry(map[string]parser.ProfileSpec{"cisco_nxos": nxos.ProfileSpec()})
	if e != nil {
		panic(e)
	}
	return r
}

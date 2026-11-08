package bootstrap

import (
	"context"

	"github.com/gatework/go-net-connector/connector"
	"github.com/gatework/go-vxlan/adapter/netconnector"
	"github.com/gatework/go-vxlan/collect"
	"github.com/gatework/go-vxlan/internal/workflow/apply"
	"github.com/gatework/go-vxlan/parser"
	"github.com/gatework/go-vxlan/vendors"
)

// OpenFunc composes a transport configuration with a borrowing session opener.
type OpenFunc func(connector.ConnectionConfig) collect.OpenSession

// Dependencies groups application composition without a service locator.
type Dependencies struct {
	Open     OpenFunc
	Profiles *parser.Registry
}

func NewDependencies(open OpenFunc) Dependencies {
	if open == nil {
		open = netconnector.Open
	}
	return Dependencies{Open: open, Profiles: vendors.NewBuiltinRegistry()}
}

// Application binds credentials and the strict host-key policy to one target.
// The complete precheck, write, and verification operation borrows one session.
func Application(c Config, host string, port int, open OpenFunc) (apply.Opener, error) {
	settings, err := Credentials(c)
	if err != nil {
		return nil, err
	}
	settings.Host, settings.Port, settings.HostKeyPolicy = host, port, "strict"
	return func(ctx context.Context, fn func(context.Context, apply.Session) error) error {
		return open(settings)(ctx, func(operationCtx context.Context, session collect.Session) error {
			return fn(operationCtx, netconnector.ConfigurationSession{Session: session})
		})
	}, nil
}

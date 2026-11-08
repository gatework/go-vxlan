package bootstrap

import (
	"time"

	"github.com/gatework/go-net-connector/connector"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

// Settings is the validated runtime snapshot. Values remains the configuration
// document for --show-config; collection and connection setup consume this type.
// Credentials are populated only when preparing a device operation.
type Settings struct {
	Directory  string
	Parallel   int
	Dimensions []string
	FabricKey  any
	Connection connector.ConnectionConfig
}

func runtimeSettings(values vxlan.Record) Settings {
	ssh := record.Map(values["ssh"])
	port := 22
	if value, ok := ssh["port"]; ok {
		port = int(record.NumberFloat(value))
	}
	return Settings{
		Directory: record.String(values["directory"]), Parallel: int(record.NumberFloat(values["parallel"])),
		Dimensions: record.Texts(values["dimensions"]), FabricKey: record.Copy(values["fabric"]),
		Connection: connector.ConnectionConfig{
			Protocol: connector.ProtocolSSH, Port: port,
			HostKeyPolicy: connector.HostKeyPolicy(record.String(ssh["host_key_policy"])), KnownHosts: record.String(ssh["known_hosts"]),
			LoginTimeout:   time.Duration(record.NumberFloat(ssh["login_timeout"]) * float64(time.Second)),
			CommandTimeout: time.Duration(record.NumberFloat(ssh["command_timeout"]) * float64(time.Second)),
		},
	}
}

package bootstrap

import (
	"time"

	"github.com/gatework/go-net-connector/connector"
	vxlan "github.com/gatework/go-vxlan"
	"github.com/gatework/go-vxlan/internal/record"
)

// Settings is the validated runtime snapshot. Values remains the configuration
// document for --show-config; collection and connection setup consume this type.
// Credentials and inventory capabilities are frozen before the snapshot escapes.
type Settings struct {
	Directory      string
	Parallel       int
	Dimensions     []string
	FabricKey      any
	Connection     connector.ConnectionConfig
	policy         vxlan.Record
	inventory      inventorySettings
	inventoryError error
}

func (c *Config) freeze() {
	c.runtime = runtimeSettings(c.Values)
	if c.Policy != nil {
		c.runtime.policy = record.Clone(c.Policy)
	}
	c.runtime.Connection.Username = credential(c.Environment, "NC_CISCO_NXOS_USERNAME", "NC_DEVICE_USERNAME")
	c.runtime.Connection.Password = credential(c.Environment, "NC_CISCO_NXOS_PASSWORD", "NC_DEVICE_PASSWORD")
	c.runtime.Connection.EnablePassword = c.Environment["NC_ENABLE_PASSWORD"]
	// Preserve source/credential validation timing: a display-only command does
	// not need working inventory credentials, while FetchInventory reports errors.
	c.runtime.inventory, c.runtime.inventoryError = inventorySettingsFor(*c)
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

package bootstrap

import (
	"fmt"
	"strings"

	"github.com/gatework/go-net-connector/connector"
)

func Credentials(c Config) (connector.ConnectionConfig, error) {
	secret := func(vendor, general string) string {
		v := c.Environment[vendor]
		if strings.TrimSpace(v) == "" {
			v = c.Environment[general]
		}
		return v
	}
	username := secret("NC_CISCO_NXOS_USERNAME", "NC_DEVICE_USERNAME")
	if strings.TrimSpace(username) == "" {
		return connector.ConnectionConfig{}, fmt.Errorf("请设置 NC_DEVICE_USERNAME 或 NC_CISCO_NXOS_USERNAME")
	}

	settings := c.runtime.Connection
	settings.Username = username
	settings.Password = secret("NC_CISCO_NXOS_PASSWORD", "NC_DEVICE_PASSWORD")
	settings.EnablePassword = c.Environment["NC_ENABLE_PASSWORD"]
	return settings, nil
}

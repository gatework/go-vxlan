package bootstrap

import (
	"fmt"
	"strings"

	"github.com/gatework/go-net-connector/connector"
)

func credential(environment map[string]string, vendor, general string) string {
	v := environment[vendor]
	if strings.TrimSpace(v) == "" {
		v = environment[general]
	}
	return v
}

// Credentials resolves runtime connection options without placing secrets in report evidence.
func Credentials(c Config) (connector.ConnectionConfig, error) {
	settings := c.runtime.Connection
	if strings.TrimSpace(settings.Username) == "" {
		return connector.ConnectionConfig{}, fmt.Errorf("请设置 NC_DEVICE_USERNAME 或 NC_CISCO_NXOS_USERNAME")
	}
	return settings, nil
}

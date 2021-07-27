package main

import (
	gkwp "github.com/hashicorp/go-kms-wrapping/plugin"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
	"github.com/hashicorp/go-plugin"
	gp "github.com/hashicorp/go-plugin"
)

var HandshakeConfig = plugin.HandshakeConfig{
	MagicCookieKey:   "HASHICORP_GKMS_AEAD_PLUGIN",
	MagicCookieValue: "Hi there!",
}

func main() {
	gp.Serve(&gp.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]gp.PluginSet{
			1: gp.PluginSet{
				"wrapping": gkwp.NewWrapper(aead.NewWrapper()),
			},
		},
		GRPCServer: gp.DefaultGRPCServer,
	})
}

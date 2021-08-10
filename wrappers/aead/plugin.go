package aead

import (
	gkwp "github.com/hashicorp/go-kms-wrapping/plugin/v2"
	"github.com/hashicorp/go-plugin"
)

func ServePlugin() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: gkwp.HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {"wrapping": gkwp.NewWrapper(NewWrapper())},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

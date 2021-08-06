package aead

import (
	gkwp "github.com/hashicorp/go-kms-wrapping/plugin/v2"
	"github.com/hashicorp/go-plugin"
)

var PluginHandshakeConfig = plugin.HandshakeConfig{
	MagicCookieKey:   "HASHICORP_GKMS_AEAD_PLUGIN",
	MagicCookieValue: "Hi there!",
}

func ServePlugin() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: PluginHandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {"wrapping": gkwp.NewWrapper(NewWrapper())},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

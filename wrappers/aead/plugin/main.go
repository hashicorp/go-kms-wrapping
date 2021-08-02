package main

import (
	gkwp "github.com/hashicorp/go-kms-wrapping/plugin/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
	gp "github.com/hashicorp/go-plugin"
)

func main() {
	gp.Serve(&gp.ServeConfig{
		HandshakeConfig: aead.PluginHandshakeConfig,
		VersionedPlugins: map[int]gp.PluginSet{
			1: {"wrapping": gkwp.NewWrapper(aead.NewWrapper())},
		},
		GRPCServer: gp.DefaultGRPCServer,
	})
}

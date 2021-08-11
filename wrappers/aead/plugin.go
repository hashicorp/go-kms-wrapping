package aead

import (
	gkwp "github.com/hashicorp/go-kms-wrapping/plugin/v2"
	"github.com/hashicorp/go-plugin"
)

func ServePlugin() error {
	wrapServer, err := gkwp.NewWrapperServer(NewWrapper())
	if err != nil {
		return err
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: gkwp.HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {"wrapping": wrapServer},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
	return nil
}

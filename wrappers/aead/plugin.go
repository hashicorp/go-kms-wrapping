package aead

import (
	"github.com/hashicorp/go-hclog"
	gkwp "github.com/hashicorp/go-kms-wrapping/plugin/v2"
	"github.com/hashicorp/go-plugin"
)

func ServePlugin(opt ...Option) error {
	opts := getOpts(opt...)
	logger := opts.withLogger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	wrapServer, err := gkwp.NewWrapperServer(NewWrapper())
	if err != nil {
		return err
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: gkwp.HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {"wrapping": wrapServer},
		},
		Logger:     logger,
		GRPCServer: plugin.DefaultGRPCServer,
	})
	return nil
}

package plugin

import (
	gkwp "github.com/hashicorp/go-kms-wrapping/plugin"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
	gp "github.com/hashicorp/go-plugin"
)

func main() {
	gp.Serve(&gp.ServeConfig{
		VersionedPlugins: map[int]gp.PluginSet{
			1: gp.PluginSet{
				"wrapping": &gkwp.NewWrapper(aead.NewWrapper()),
			},
		},
		GRPCServer: gp.DefaultGRPCServer,
	})
}

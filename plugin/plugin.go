package plugin

import (
	context "context"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-plugin"
	gp "github.com/hashicorp/go-plugin"
	grpc "google.golang.org/grpc"
)

// HandshakeConfig is a shared config that can be used regardless of wrapper, to
// avoid having to know type-specific things about each plugin
var HandshakeConfig = gp.HandshakeConfig{
	MagicCookieKey:   "HASHICORP_GKW_PLUGIN",
	MagicCookieValue: "wrapper",
}

// ServePlugin is a generic function to start serving a wrapper as a plugin
func ServePlugin(wrapper wrapping.Wrapper, opt ...Option) error {
	opts, err := getOpts(opt...)
	if err != nil {
		return err
	}
	wrapServer, err := NewWrapperServer(wrapper)
	if err != nil {
		return err
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		VersionedPlugins: map[int]plugin.PluginSet{
			1: {"wrapping": wrapServer},
		},
		Logger:     opts.withLogger,
		GRPCServer: plugin.DefaultGRPCServer,
	})
	return nil
}

// wrapper embeds Plugin and is used as the top-level
type wrapper struct {
	gp.Plugin

	impl          wrapping.Wrapper
	initFinalizer bool
}

func NewWrapperServer(impl wrapping.Wrapper) (*wrapper, error) {
	if impl == nil {
		return nil, fmt.Errorf("empty underlying wrapper passed in")
	}
	return &wrapper{
		impl: impl,
	}, nil
}

func NewWrapperClient(opt ...Option) (*wrapper, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}
	return &wrapper{
		initFinalizer: opts.withInitFinalizeInterface,
	}, nil
}

func (w *wrapper) GRPCServer(broker *gp.GRPCBroker, s *grpc.Server) error {
	RegisterWrappingServer(s, &wrapServer{impl: w.impl})
	if initFinalizer, ok := w.impl.(wrapping.InitFinalizer); ok {
		RegisterInitFinalizeServer(s, &initFinalizeServer{impl: initFinalizer})
	}
	return nil
}

func (w *wrapper) GRPCClient(ctx context.Context, broker *gp.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	ret := &wrapClient{impl: NewWrappingClient(c)}
	if w.initFinalizer {
		return &wrapInitFinalizerClient{wrapClient: ret, impl: NewInitFinalizeClient(c)}, nil
	}
	return ret, nil
}

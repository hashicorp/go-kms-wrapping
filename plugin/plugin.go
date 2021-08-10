package plugin

import (
	context "context"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	gp "github.com/hashicorp/go-plugin"
	grpc "google.golang.org/grpc"
)

// HandshakeConfig is a shared config that can be used regardless of wrapper, to
// avoid having to know type-specific things about each plugin
var HandshakeConfig = gp.HandshakeConfig{
	MagicCookieKey:   "HASHICORP_GKW_PLUGIN",
	MagicCookieValue: "wrapper",
}

// wrapper embeds Plugin and is used as the top-level
type wrapper struct {
	gp.Plugin

	impl wrapping.Wrapper
}

func NewWrapper(impl wrapping.Wrapper) *wrapper {
	return &wrapper{
		impl: impl,
	}
}

func (w *wrapper) GRPCServer(broker *gp.GRPCBroker, s *grpc.Server) error {
	RegisterWrappingServer(s, &wrapServer{impl: w.impl})
	return nil
}

func (w *wrapper) GRPCClient(ctx context.Context, broker *gp.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &wrapClient{impl: NewWrappingClient(c)}, nil
}

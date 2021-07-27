package plugin

import (
	context "context"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	gp "github.com/hashicorp/go-plugin"
	grpc "google.golang.org/grpc"
)

type wrapClient struct {
	impl WrappingClient
}

func (w *wrapper) GRPCClient(ctx context.Context, broker *gp.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &wrapClient{impl: NewWrappingClient(c)}, nil
}

func (wc *wrapClient) Type(ctx context.Context) (wrapping.WrapperType, error) {
	resp, err := wc.impl.Type(ctx, new(TypeRequest))
	if err != nil {
		return wrapping.WrapperTypeUnknown, err
	}
	return wrapping.WrapperType(resp.Type), nil
}

func (wc *wrapClient) KeyId(ctx context.Context) (string, error) {
	resp, err := wc.impl.KeyId(ctx, new(KeyIdRequest))
	if err != nil {
		return "", err
	}
	return resp.KeyId, nil
}

func (wc *wrapClient) SetConfig(ctx context.Context, options ...interface{}) (*wrapping.WrapperConfig, error) {
	opts := wrapping.GetOpts(options...)
	resp, err := wc.impl.SetConfig(ctx, &SetConfigRequest{
		Options: &opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.WrapperConfig, nil
}

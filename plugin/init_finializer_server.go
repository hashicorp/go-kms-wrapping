package plugin

import (
	context "context"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

type initFinalizeServer struct {
	UnimplementedInitFinalizeServer
	impl wrapping.InitFinalizer
}

func (ifs *initFinalizeServer) Init(ctx context.Context, req *InitRequest) (*InitResponse, error) {
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	if err := ifs.impl.Init(
		ctx,
		wrapping.WithWrapperOptions(opts.WithWrapperOptions),
	); err != nil {
		return nil, err
	}
	return &InitResponse{}, nil
}

func (ifs *initFinalizeServer) Finalize(ctx context.Context, req *FinalizeRequest) (*FinalizeResponse, error) {
	if err := ifs.impl.Finalize(
		ctx,
	); err != nil {
		return nil, err
	}
	return &FinalizeResponse{}, nil
}

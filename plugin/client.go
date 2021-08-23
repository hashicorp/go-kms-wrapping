package plugin

import (
	context "context"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

var (
	_ wrapping.Wrapper       = (*wrapClient)(nil)
	_ wrapping.InitFinalizer = (*wrapInitFinalizerClient)(nil)
	_ wrapping.InitFinalizer = (*wrapInitFinalizerHmacComputerClient)(nil)
	_ wrapping.HmacComputer  = (*wrapInitFinalizerHmacComputerClient)(nil)
)

type wrapClient struct {
	impl WrappingClient
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

func (wc *wrapClient) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.impl.SetConfig(ctx, &SetConfigRequest{
		Options: opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.WrapperConfig, nil
}

func (wc *wrapClient) Encrypt(ctx context.Context, pt []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.impl.Encrypt(ctx, &EncryptRequest{
		Plaintext: pt,
		Options:   opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (wc *wrapClient) Decrypt(ctx context.Context, ct *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.impl.Decrypt(ctx, &DecryptRequest{
		Ciphertext: ct,
		Options:    opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

type wrapInitFinalizerClient struct {
	*wrapClient
	impl InitFinalizeClient
}

func (ifc *wrapInitFinalizerClient) Init(ctx context.Context, options ...wrapping.Option) error {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return err
	}
	_, err = ifc.impl.Init(ctx, &InitRequest{
		Options: opts,
	})
	return err
}

func (ifc *wrapInitFinalizerClient) Finalize(ctx context.Context, options ...wrapping.Option) error {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return err
	}
	_, err = ifc.impl.Finalize(ctx, &FinalizeRequest{
		Options: opts,
	})
	return err
}

type wrapInitFinalizerHmacComputerClient struct {
	*wrapInitFinalizerClient
	impl HmacComputerClient
}

func (wc *wrapInitFinalizerHmacComputerClient) HmacKeyId(ctx context.Context) (string, error) {
	resp, err := wc.impl.HmacKeyId(ctx, new(HmacKeyIdRequest))
	if err != nil {
		return "", err
	}
	return resp.KeyId, nil
}

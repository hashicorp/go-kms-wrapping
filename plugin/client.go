package plugin

import (
	context "context"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
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

func (wc *wrapClient) Encrypt(ctx context.Context, pt []byte, options ...interface{}) (*wrapping.BlobInfo, error) {
	opts := wrapping.GetOpts(options...)
	resp, err := wc.impl.Encrypt(ctx, &EncryptRequest{
		Plaintext: pt,
		Options:   &opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (wc *wrapClient) Decrypt(ctx context.Context, ct *wrapping.BlobInfo, options ...interface{}) ([]byte, error) {
	opts := wrapping.GetOpts(options...)
	resp, err := wc.impl.Decrypt(ctx, &DecryptRequest{
		Ciphertext: ct,
		Options:    &opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

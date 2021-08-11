package plugin

import (
	context "context"
	"log"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/kr/pretty"
)

type wrapServer struct {
	UnimplementedWrappingServer
	impl wrapping.Wrapper
}

func (ws *wrapServer) Type(ctx context.Context, req *TypeRequest) (*TypeResponse, error) {
	typ, err := ws.impl.Type(ctx)
	if err != nil {
		return nil, err
	}
	return &TypeResponse{Type: typ.String()}, nil
}

func (ws *wrapServer) KeyId(ctx context.Context, req *KeyIdRequest) (*KeyIdResponse, error) {
	keyId, err := ws.impl.KeyId(ctx)
	if err != nil {
		return nil, err
	}
	return &KeyIdResponse{KeyId: keyId}, nil
}

func (ws *wrapServer) SetConfig(ctx context.Context, req *SetConfigRequest) (*SetConfigResponse, error) {
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	log.Println("wrapServer", pretty.Sprint(opts))
	wc, err := ws.impl.SetConfig(
		ctx,
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithWrapperOptions(opts.WithWrapperOptions),
	)
	if err != nil {
		return nil, err
	}
	return &SetConfigResponse{WrapperConfig: wc}, nil
}

func (ws *wrapServer) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	ct, err := ws.impl.Encrypt(
		ctx,
		req.Plaintext,
		wrapping.WithAad(opts.WithAad),
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithWrapperOptions(opts.WithWrapperOptions),
	)
	if err != nil {
		return nil, err
	}
	return &EncryptResponse{Ciphertext: ct}, nil
}

func (ws *wrapServer) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	pt, err := ws.impl.Decrypt(
		ctx,
		req.Ciphertext,
		wrapping.WithAad(opts.WithAad),
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithWrapperOptions(opts.WithWrapperOptions),
	)
	if err != nil {
		return nil, err
	}
	return &DecryptResponse{Plaintext: pt}, nil
}

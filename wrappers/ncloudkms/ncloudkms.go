package ncloudkms

import (
	"context"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	sdk "github.com/jayground8/ncloud-sdk-go/client"
	"github.com/jayground8/ncloud-sdk-go/ncloud/credentials"
)

const (
	EnvNcloudKmsKeyTag = "NCLOUD_KMS_KEY_TAG"
)

type Wrapper struct {
	keyId        string
	currentKeyId *atomic.Value

	client *sdk.APIClient
	logger hclog.Logger
}

var _ wrapping.Wrapper = (*Wrapper)(nil)

func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	k.logger = opts.withLogger

	switch {
	case os.Getenv(EnvNcloudKmsKeyTag) != "":
		k.keyId = os.Getenv(EnvNcloudKmsKeyTag)
	case opts.WithKeyId != "":
		k.keyId = opts.WithKeyId
	default:
		return nil, errors.New("key tag is required")
	}

	if k.client == nil {
		credentials := credentials.NewValueProviderCreds("", "")
		config := sdk.NewConfiguration(credentials)
		client := sdk.NewAPIClient(config)
		k.client = client
	}

	wrapConfig := new(wrapping.WrapperConfig)
	return wrapConfig, nil
}

func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeNcloudKms, nil
}

func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

func (k *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}
	b64EncodedValue := b64.StdEncoding.EncodeToString(env.Key)
	body := sdk.NewEncryptRequest(b64EncodedValue)
	req := k.client.KmsAPI.Encrypt(context.Background(), k.keyId).EncryptRequest(*body)
	value, _, err := k.client.KmsAPI.EncryptExecute(req)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}
	data := value.GetData()
	ciphertext := data.GetCiphertext()
	if ciphertext == "" {
		return nil, fmt.Errorf("failed to get data from kms: %s", value.GetMsg())
	}

	k.currentKeyId.Store(k.keyId)

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			// Storing current key version in case we want to re-wrap older entries
			KeyId:      k.keyId,
			WrappedKey: []byte(ciphertext),
		},
	}

	return ret, nil
}

func (k *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	body := sdk.NewDecryptRequest(string(in.KeyInfo.WrappedKey))
	req := k.client.KmsAPI.Decrypt(context.Background(), k.keyId).DecryptRequest(*body)
	value, _, err := k.client.KmsAPI.DecryptExecute(req)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}
	data := value.GetData()
	b64EncodedPlaintext := data.GetPlaintext()
	b64DecodedPlaintext, _ := b64.StdEncoding.DecodeString(b64EncodedPlaintext)

	envInfo := &wrapping.EnvelopeInfo{
		Key:        b64DecodedPlaintext,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

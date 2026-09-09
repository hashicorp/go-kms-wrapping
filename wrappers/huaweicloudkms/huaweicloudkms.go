// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package huaweicloudkms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	coreregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/region"
	kms "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/region"
)

// These constants contain the accepted env vars; the Vault one is for backwards compat
const (
	EnvHuaweiCloudKmsWrapperKeyId   = "HUAWEICLOUDKMS_WRAPPER_KEY_ID"
	EnvVaultHuaweiCloudKmsSealKeyId = "VAULT_HUAWEICLOUDKMS_SEAL_KEY_ID"
)

const (
	// HuaweiCloudKmsEnvelopeAesGcmEncrypt is when a data encryption key is generated and
	// the data is encrypted with AES-GCM and the key is encrypted with KMS
	HuaweiCloudKmsEnvelopeAesGcmEncrypt = iota
	// HuaweiCloudKmsEncrypt is used to directly encrypt the data with KMS
	HuaweiCloudKmsEncrypt
)

// Wrapper is a Wrapper that uses HuaweiCloud's KMS
type Wrapper struct {
	client       kmsClient
	region       string
	project      string
	keyId        string
	currentKeyId *atomic.Value
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new HuaweiCloud Wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")
	return k
}

// SetConfig sets the fields on the HuaweiCloudKmsWrapper object based on
// values from the config parameter.
//
// Order of precedence HuaweiCloud values:
// * Environment variable
// * Value from Vault configuration file
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	env := func(name string) string {
		if opts.WithDisallowEnvVars {
			return ""
		}
		return os.Getenv(name)
	}

	// Check and set KeyId
	k.keyId, err = getConfig("kms_key_id",
		env(EnvHuaweiCloudKmsWrapperKeyId),
		env(EnvVaultHuaweiCloudKmsSealKeyId),
		opts.WithKeyId)
	if err != nil {
		return nil, err
	}

	if k.client == nil {
		k.region, err = getConfig("region", env("HUAWEICLOUD_REGION"), opts.withRegion)
		if err != nil {
			return nil, err
		}
		// Project ID is optional: the SDK resolves it via IAM when empty.
		k.project = firstNonEmpty(env("HUAWEICLOUD_PROJECT"), opts.withProject)

		accessKey, err := getConfig("access_key", env("HUAWEICLOUD_ACCESS_KEY"), opts.withAccessKey)
		if err != nil {
			return nil, err
		}
		secretKey, err := getConfig("secret_key", env("HUAWEICLOUD_SECRET_KEY"), opts.withSecretKey)
		if err != nil {
			return nil, err
		}
		identityEndpoint := firstNonEmpty(env("HUAWEICLOUD_IDENTITY_ENDPOINT"), opts.withIdentityEndpoint)
		endpoint := firstNonEmpty(env("HUAWEICLOUD_KMS_ENDPOINT"), opts.withEndpoint)

		client, err := buildKmsClient(k.region, k.project, accessKey, secretKey, identityEndpoint, endpoint)
		if err != nil {
			return nil, err
		}
		k.client = client
	}

	// Test the client connection using provided key ID
	keyInfo, err := k.client.ListKeyDetail(&model.ListKeyDetailRequest{
		Body: &model.OperateKeyRequestBody{KeyId: k.keyId},
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching HuaweiCloud KMS key information: %w", err)
	}
	if keyInfo == nil || keyInfo.KeyInfo == nil || keyInfo.KeyInfo.KeyId == nil || *keyInfo.KeyInfo.KeyId == "" {
		return nil, errors.New("no key information returned")
	}

	// Store the current key id. If using a key alias, this will point to the actual
	// unique key that that was used for this encrypt operation.
	k.currentKeyId.Store(*keyInfo.KeyInfo.KeyId)

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["region"] = k.region
	wrapConfig.Metadata["project"] = k.project
	wrapConfig.Metadata["kms_key_id"] = k.keyId

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeHuaweiCloudKms, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the the HuaweiCloud CMK.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	if opts.WithoutEnvelope {
		keyId, ciphertext, err := k.kmsEncrypt(plaintext)
		if err != nil {
			return nil, err
		}
		return &wrapping.BlobInfo{
			Ciphertext: ciphertext,
			KeyInfo: &wrapping.KeyInfo{
				Mechanism: HuaweiCloudKmsEncrypt,
				KeyId:     keyId,
			},
		}, nil
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}
	keyId, wrappedKey, err := k.kmsEncrypt(env.Key)
	if err != nil {
		return nil, err
	}
	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  HuaweiCloudKmsEnvelopeAesGcmEncrypt,
			KeyId:      keyId,
			WrappedKey: wrappedKey,
		},
	}, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	if in.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}

	switch in.KeyInfo.Mechanism {
	case HuaweiCloudKmsEncrypt:
		plaintext, err := k.kmsDecrypt(in.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data: %w", err)
		}
		return plaintext, nil

	case HuaweiCloudKmsEnvelopeAesGcmEncrypt:
		envelopeKey, err := k.kmsDecrypt(in.KeyInfo.WrappedKey)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
		}
		plaintext, err := wrapping.EnvelopeDecrypt(&wrapping.EnvelopeInfo{
			Key:        envelopeKey,
			Iv:         in.Iv,
			Ciphertext: in.Ciphertext,
		}, opt...)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data: %w", err)
		}
		return plaintext, nil

	default:
		return nil, fmt.Errorf("invalid mechanism: %d", in.KeyInfo.Mechanism)
	}
}

// kmsEncrypt encrypts plaintext with the configured CMK. KMS only accepts
// text, so the bytes are base64 encoded first. Returns the key id used and
// the ciphertext as KMS returns it.
func (k *Wrapper) kmsEncrypt(plaintext []byte) (string, []byte, error) {
	out, err := k.client.EncryptData(&model.EncryptDataRequest{
		Body: &model.EncryptDataRequestBody{
			KeyId:     k.keyId,
			PlainText: base64.StdEncoding.EncodeToString(plaintext),
		},
	})
	if err != nil {
		return "", nil, fmt.Errorf("error encrypting data: %w", err)
	}
	if out == nil || out.CipherText == nil {
		return "", nil, errors.New("no ciphertext returned")
	}

	keyId := k.keyId
	if out.KeyId != nil && *out.KeyId != "" {
		keyId = *out.KeyId
	}
	k.currentKeyId.Store(keyId)
	return keyId, []byte(*out.CipherText), nil
}

// kmsDecrypt is the inverse of kmsEncrypt. KeyId is not passed because
// HuaweiCloud resolves it from the ciphertext metadata.
func (k *Wrapper) kmsDecrypt(ciphertext []byte) ([]byte, error) {
	out, err := k.client.DecryptData(&model.DecryptDataRequest{
		Body: &model.DecryptDataRequestBody{CipherText: string(ciphertext)},
	})
	if err != nil {
		return nil, err
	}
	if out == nil || out.PlainText == nil {
		return nil, errors.New("no plaintext returned")
	}
	plaintext, err := base64.StdEncoding.DecodeString(*out.PlainText)
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding plaintext: %w", err)
	}
	return plaintext, nil
}

func getConfig(name string, values ...string) (string, error) {
	if v := firstNonEmpty(values...); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("'%s' not found for HuaweiCloud kms wrapper configuration", name)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func buildKmsClient(regionId, projectId, accessKey, secretKey, identityEndpoint, endpoint string) (*kms.KmsClient, error) {
	credBuilder := basic.NewCredentialsBuilder().WithAk(accessKey).WithSk(secretKey)
	if projectId != "" {
		credBuilder = credBuilder.WithProjectId(projectId)
	}
	if identityEndpoint != "" {
		credBuilder = credBuilder.WithIamEndpointOverride(identityEndpoint)
	}
	cred, err := credBuilder.SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("error building HuaweiCloud credentials: %w", err)
	}

	// An explicit endpoint lets unlisted regions work without an SDK upgrade.
	var reg *coreregion.Region
	if endpoint != "" {
		reg = coreregion.NewRegion(regionId, endpoint)
	} else if reg, err = region.SafeValueOf(regionId); err != nil {
		return nil, fmt.Errorf("error resolving HuaweiCloud KMS region %q: %w", regionId, err)
	}

	hcClient, err := kms.KmsClientBuilder().
		WithRegion(reg).
		WithCredential(cred).
		SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("error building HuaweiCloud KMS client: %w", err)
	}
	return kms.NewKmsClient(hcClient), nil
}

type kmsClient interface {
	ListKeyDetail(request *model.ListKeyDetailRequest) (*model.ListKeyDetailResponse, error)
	EncryptData(request *model.EncryptDataRequest) (*model.EncryptDataResponse, error)
	DecryptData(request *model.DecryptDataRequest) (*model.DecryptDataResponse, error)
}

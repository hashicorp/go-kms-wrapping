// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tencentcloudkms

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sync/atomic"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	kms "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/kms/v20190118"
)

// These constants are TencentCloud accepted env vars
const (
	PROVIDER_SECRET_ID      = "TENCENTCLOUD_SECRET_ID"
	PROVIDER_SECRET_KEY     = "TENCENTCLOUD_SECRET_KEY"
	PROVIDER_SECURITY_TOKEN = "TENCENTCLOUD_SECURITY_TOKEN"
	PROVIDER_REGION         = "TENCENTCLOUD_REGION"
	PROVIDER_KMS_KEY_ID     = "TENCENTCLOUD_KMS_KEY_ID"
)

// Wrapper is a wrapper that uses TencentCloud KMS
type Wrapper struct {
	accessKey    string
	secretKey    string
	sessionToken string
	region       string

	keyId        string
	currentKeyId *atomic.Value

	client kmsClient
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper returns a new TencentCloud wrapper
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	k.currentKeyId.Store("")

	return k
}

// SetConfig sets the fields on the wrapper object based on TencentCloud config parameter
//
// Order of precedence values:
// * Environment variable
// * Instance metadata role
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	switch {
	case os.Getenv(PROVIDER_KMS_KEY_ID) != "":
		k.keyId = os.Getenv(PROVIDER_KMS_KEY_ID)
	case opts.WithKeyId != "":
		k.keyId = wrapping.QuietParsePath(opts.WithKeyId)
	default:
		return nil, fmt.Errorf("'key_id' not found for TencentCloud kms wrapper configuration")
	}

	switch {
	case os.Getenv(PROVIDER_REGION) != "":
		k.region = os.Getenv(PROVIDER_REGION)
	case opts.withRegion != "":
		k.region = opts.withRegion
	}

	switch {
	case os.Getenv(PROVIDER_SECRET_ID) != "":
		k.accessKey = os.Getenv(PROVIDER_SECRET_ID)
	case opts.withAccessKey != "":
		k.accessKey = wrapping.QuietParsePath(opts.withAccessKey)
	default:
		return nil, fmt.Errorf("'access_key' not found for TencentCloud KMS wrapper configuration")
	}

	switch {
	case os.Getenv(PROVIDER_SECRET_KEY) != "":
		k.secretKey = os.Getenv(PROVIDER_SECRET_KEY)
	case opts.withSecretKey != "":
		k.secretKey = wrapping.QuietParsePath(opts.withSecretKey)
	default:
		return nil, fmt.Errorf("'secret_key' not found for TencentCloud KMS wrapper configuration")
	}

	switch {
	case os.Getenv(PROVIDER_SECURITY_TOKEN) != "":
		k.sessionToken = os.Getenv(PROVIDER_SECURITY_TOKEN)
	case opts.withSessionToken != "":
		k.sessionToken = wrapping.QuietParsePath(opts.withSessionToken)
	}

	if k.client == nil {
		cpf := profile.NewClientProfile()
		cpf.HttpProfile.ReqMethod = "POST"
		cpf.HttpProfile.ReqTimeout = 300
		cpf.Language = "en-US"

		credential := common.NewTokenCredential(k.accessKey, k.secretKey, k.sessionToken)
		client, err := kms.NewClient(credential, k.region, cpf)
		if err != nil {
			return nil, fmt.Errorf("error initializing TencentCloud KMS client: %w", err)
		}

		input := kms.NewDescribeKeyRequest()
		input.KeyId = &k.keyId
		keyInfo, err := client.DescribeKey(input)
		if err != nil {
			return nil, fmt.Errorf("error fetching TencentCloud KMS information: %w", err)
		}

		if keyInfo.Response.KeyMetadata == nil || keyInfo.Response.KeyMetadata.KeyId == nil {
			return nil, fmt.Errorf("no key information return")
		}

		k.currentKeyId.Store(*keyInfo.Response.KeyMetadata.KeyId)
		k.client = client
	}

	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["region"] = k.region
	wrapConfig.Metadata["kms_key_id"] = k.keyId

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeTencentCloudKms, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the the TencentCloud KMS.
// This returns the ciphertext, and/or any errors from this call.
// This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	input := kms.NewEncryptRequest()
	input.KeyId = &k.keyId
	input.Plaintext = common.StringPtr(base64.StdEncoding.EncodeToString(env.Key))

	output, err := k.client.Encrypt(input)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	keyId := *output.Response.KeyId
	k.currentKeyId.Store(keyId)

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      keyId,
			WrappedKey: []byte(*output.Response.CiphertextBlob),
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext using the the TencentCloud KMS.
// This should be called after the KMS client has been instantiated.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	input := kms.NewDecryptRequest()
	input.CiphertextBlob = common.StringPtr(string(in.KeyInfo.WrappedKey))

	output, err := k.client.Decrypt(input)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(*output.Response.Plaintext)
	if err != nil {
		return nil, err
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        keyBytes,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}

	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

type kmsClient interface {
	Decrypt(request *kms.DecryptRequest) (response *kms.DecryptResponse, err error)
	DescribeKey(request *kms.DescribeKeyRequest) (response *kms.DescribeKeyResponse, err error)
	Encrypt(request *kms.EncryptRequest) (response *kms.EncryptResponse, err error)
}

// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package tencentcloudkms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	kms "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/kms/v20190118"
	sts "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sts/v20180813"
)

// These constants are TencentCloud accepted env vars
const (
	PROVIDER_SECRET_ID       = "TENCENTCLOUD_SECRET_ID"
	PROVIDER_SECRET_KEY      = "TENCENTCLOUD_SECRET_KEY"
	PROVIDER_SECURITY_TOKEN  = "TENCENTCLOUD_SECURITY_TOKEN"
	PROVIDER_REGION          = "TENCENTCLOUD_REGION"
	PROVIDER_KMS_KEY_ID      = "TENCENTCLOUD_KMS_KEY_ID"
	PROVIDER_ROLE_ARN        = "TENCENTCLOUD_ROLE_ARN"
	PROVIDER_ROLE_SESSION_NM = "TENCENTCLOUD_ROLE_SESSION_NAME"
	PROVIDER_ROLE_EXTERN_ID  = "TENCENTCLOUD_ROLE_EXTERNAL_ID"
	PROVIDER_ROLE_DURATION   = "TENCENTCLOUD_ROLE_DURATION_SECONDS"
)

// defaultRoleSessionName is used when a role is assumed but no session name
// was supplied by the caller.
const defaultRoleSessionName = "go-kms-wrapping-session"

const (
	// TencentCloudKmsEnvelopeAesGcmEncrypt is when a data encryption key is generated and
	// the data is encrypted with AES-GCM and the key is encrypted with KMS
	TencentCloudKmsEnvelopeAesGcmEncrypt = iota
	// TencentCloudKmsEncrypt is used to directly encrypt the data with KMS
	TencentCloudKmsEncrypt
)

// Wrapper is a wrapper that uses TencentCloud KMS
type Wrapper struct {
	accessKey    string
	secretKey    string
	sessionToken string
	region       string

	// Optional CAM role to assume. When roleArn is set, the accessKey/secretKey
	// above are treated as the base credentials used to call STS AssumeRole, and
	// the temporary credentials returned are what actually talk to KMS.
	roleArn             string
	roleSessionName     string
	roleExternalId      string
	roleDurationSeconds uint64

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

	// Note: when WithDisallowEnvVars is set (which is what Vault does, since it
	// resolves env vars into the config map itself) we deliberately ignore the
	// environment here. This matches the behaviour of the other cloud wrappers
	// (see alicloudkms and awskms) and prevents env vars from silently
	// overriding an explicitly supplied configuration.
	switch {
	case os.Getenv(PROVIDER_KMS_KEY_ID) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyId = os.Getenv(PROVIDER_KMS_KEY_ID)
	case opts.WithKeyId != "":
		k.keyId = opts.WithKeyId
	default:
		return nil, fmt.Errorf("'key_id' not found for TencentCloud kms wrapper configuration")
	}

	switch {
	case os.Getenv(PROVIDER_REGION) != "" && !opts.Options.WithDisallowEnvVars:
		k.region = os.Getenv(PROVIDER_REGION)
	case opts.withRegion != "":
		k.region = opts.withRegion
	}

	switch {
	case os.Getenv(PROVIDER_SECRET_ID) != "" && !opts.Options.WithDisallowEnvVars:
		k.accessKey = os.Getenv(PROVIDER_SECRET_ID)
	case opts.withAccessKey != "":
		k.accessKey = opts.withAccessKey
	default:
		return nil, fmt.Errorf("'access_key' not found for TencentCloud KMS wrapper configuration")
	}

	switch {
	case os.Getenv(PROVIDER_SECRET_KEY) != "" && !opts.Options.WithDisallowEnvVars:
		k.secretKey = os.Getenv(PROVIDER_SECRET_KEY)
	case opts.withSecretKey != "":
		k.secretKey = opts.withSecretKey
	default:
		return nil, fmt.Errorf("'secret_key' not found for TencentCloud KMS wrapper configuration")
	}

	switch {
	case os.Getenv(PROVIDER_SECURITY_TOKEN) != "" && !opts.Options.WithDisallowEnvVars:
		k.sessionToken = os.Getenv(PROVIDER_SECURITY_TOKEN)
	case opts.withSessionToken != "":
		k.sessionToken = opts.withSessionToken
	}

	switch {
	case os.Getenv(PROVIDER_ROLE_ARN) != "" && !opts.Options.WithDisallowEnvVars:
		k.roleArn = os.Getenv(PROVIDER_ROLE_ARN)
	case opts.withRoleArn != "":
		k.roleArn = opts.withRoleArn
	}

	switch {
	case os.Getenv(PROVIDER_ROLE_SESSION_NM) != "" && !opts.Options.WithDisallowEnvVars:
		k.roleSessionName = os.Getenv(PROVIDER_ROLE_SESSION_NM)
	case opts.withRoleSessionName != "":
		k.roleSessionName = opts.withRoleSessionName
	}

	switch {
	case os.Getenv(PROVIDER_ROLE_EXTERN_ID) != "" && !opts.Options.WithDisallowEnvVars:
		k.roleExternalId = os.Getenv(PROVIDER_ROLE_EXTERN_ID)
	case opts.withRoleExternalId != "":
		k.roleExternalId = opts.withRoleExternalId
	}

	k.roleDurationSeconds = opts.withRoleDurationSeconds
	if durStr := os.Getenv(PROVIDER_ROLE_DURATION); durStr != "" && !opts.Options.WithDisallowEnvVars {
		d, err := parseRoleDurationSeconds(durStr)
		if err != nil {
			return nil, err
		}
		k.roleDurationSeconds = d
	}

	if k.client == nil {
		cpf := profile.NewClientProfile()
		cpf.HttpProfile.ReqMethod = "POST"
		cpf.HttpProfile.ReqTimeout = 300
		cpf.Language = "en-US"

		credential := common.NewTokenCredential(k.accessKey, k.secretKey, k.sessionToken)

		// If a CAM role is configured, exchange the base credentials for
		// temporary credentials via STS AssumeRole and use those for KMS.
		if k.roleArn != "" {
			assumed, err := k.assumeRole(credential, cpf)
			if err != nil {
				return nil, err
			}
			credential = assumed
		}

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

// assumeRole exchanges the configured base credentials for temporary
// credentials by calling STS AssumeRole for k.roleArn. The returned credential
// is what should be used to construct the KMS client.
//
// The base credentials (access_key/secret_key, or whatever was resolved from
// the environment) only need permission to call sts:AssumeRole on the target
// role; the KMS permissions live on the assumed role itself.
func (k *Wrapper) assumeRole(baseCred common.CredentialIface, cpf *profile.ClientProfile) (*common.Credential, error) {
	stsClient, err := sts.NewClient(baseCred, k.region, cpf)
	if err != nil {
		return nil, fmt.Errorf("error initializing TencentCloud STS client: %w", err)
	}

	sessionName := k.roleSessionName
	if sessionName == "" {
		sessionName = defaultRoleSessionName
	}

	req := sts.NewAssumeRoleRequest()
	req.RoleArn = common.StringPtr(k.roleArn)
	req.RoleSessionName = common.StringPtr(sessionName)
	if k.roleExternalId != "" {
		req.ExternalId = common.StringPtr(k.roleExternalId)
	}
	if k.roleDurationSeconds != 0 {
		req.DurationSeconds = common.Uint64Ptr(k.roleDurationSeconds)
	}

	resp, err := stsClient.AssumeRole(req)
	if err != nil {
		return nil, fmt.Errorf("error assuming TencentCloud role %q: %w", k.roleArn, err)
	}
	if resp.Response == nil || resp.Response.Credentials == nil {
		return nil, errors.New("no credentials returned from TencentCloud STS AssumeRole")
	}

	creds := resp.Response.Credentials
	if creds.TmpSecretId == nil || creds.TmpSecretKey == nil || creds.Token == nil {
		return nil, errors.New("incomplete credentials returned from TencentCloud STS AssumeRole")
	}

	// Stash the temporary credentials on the wrapper so any later client
	// re-creation is consistent with what was used here.
	k.accessKey = *creds.TmpSecretId
	k.secretKey = *creds.TmpSecretKey
	k.sessionToken = *creds.Token

	return common.NewTokenCredential(k.accessKey, k.secretKey, k.sessionToken), nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeTencentCloudKms, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the TencentCloud KMS.
// This returns the ciphertext, and/or any errors from this call.
// This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	var ret *wrapping.BlobInfo
	if opts.WithoutEnvelope {
		input := kms.NewEncryptRequest()
		input.KeyId = &k.keyId
		input.Plaintext = common.StringPtr(base64.StdEncoding.EncodeToString(plaintext))

		output, err := k.client.Encrypt(input)
		if err != nil {
			return nil, fmt.Errorf("error encrypting data: %w", err)
		}

		keyId := *output.Response.KeyId
		k.currentKeyId.Store(keyId)

		ret = &wrapping.BlobInfo{
			Ciphertext: []byte(*output.Response.CiphertextBlob),
			KeyInfo: &wrapping.KeyInfo{
				Mechanism: TencentCloudKmsEncrypt,
				KeyId:     keyId,
			},
		}
	} else {
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

		ret = &wrapping.BlobInfo{
			Ciphertext: env.Ciphertext,
			Iv:         env.Iv,
			KeyInfo: &wrapping.KeyInfo{
				Mechanism:  TencentCloudKmsEnvelopeAesGcmEncrypt,
				KeyId:      keyId,
				WrappedKey: []byte(*output.Response.CiphertextBlob),
			},
		}
	}
	return ret, nil
}

// Decrypt is used to decrypt the ciphertext using the TencentCloud KMS.
// This should be called after the KMS client has been instantiated.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	if in.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}

	var plaintext []byte
	switch in.KeyInfo.Mechanism {
	case TencentCloudKmsEncrypt:
		input := kms.NewDecryptRequest()
		input.CiphertextBlob = common.StringPtr(string(in.Ciphertext))

		output, err := k.client.Decrypt(input)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data: %w", err)
		}

		plaintext, err = base64.StdEncoding.DecodeString(*output.Response.Plaintext)
		if err != nil {
			return nil, err
		}

	case TencentCloudKmsEnvelopeAesGcmEncrypt:
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

		plaintext, err = wrapping.EnvelopeDecrypt(envInfo, opt...)
		if err != nil {
			return nil, fmt.Errorf("error decrypting data: %w", err)
		}

	default:
		return nil, fmt.Errorf("invalid mechanism: %d", in.KeyInfo.Mechanism)
	}

	return plaintext, nil
}

type kmsClient interface {
	Decrypt(request *kms.DecryptRequest) (response *kms.DecryptResponse, err error)
	DescribeKey(request *kms.DescribeKeyRequest) (response *kms.DescribeKeyResponse, err error)
	Encrypt(request *kms.EncryptRequest) (response *kms.EncryptResponse, err error)
}

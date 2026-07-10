// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package scalewaykms

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	key_manager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

// These constants contain the accepted env vars; the Vault one is for backwards compat
const (
	EnvScalewayKmsWrapperKeyId   = "SCALEWAYKMS_WRAPPER_KEY_ID"
	EnvVaultScalewayKmsSealKeyId = "VAULT_SCALEWAYKMS_SEAL_KEY_ID"
	EnvScalewayRegion            = "SCW_DEFAULT_REGION"
	EnvScalewayProjectId         = "SCW_PROJECT_ID"
	EnvScalewayAccessKey         = "SCW_ACCESS_KEY"
	EnvScalewaySecretKey         = "SCW_SECRET_KEY" //nolint:gosec // env var name, not a credential
)

const (
	// maxDirectPlaintextSize is the Scaleway Key Manager limit for direct Encrypt plaintext.
	maxDirectPlaintextSize = 65535

	// ScalewayKmsEncrypt directly encrypts data with Key Manager.
	ScalewayKmsEncrypt = iota
	// ScalewayKmsEnvelopeAesGcmEncrypt uses envelope encryption (DEK + KMS-wrapped key).
	ScalewayKmsEnvelopeAesGcmEncrypt
)

// KeyManagerAPI is the subset of the Scaleway Key Manager API used by the wrapper.
type KeyManagerAPI interface {
	GetKey(req *key_manager.GetKeyRequest, opts ...scw.RequestOption) (*key_manager.Key, error)
	Encrypt(req *key_manager.EncryptRequest, opts ...scw.RequestOption) (*key_manager.EncryptResponse, error)
	Decrypt(req *key_manager.DecryptRequest, opts ...scw.RequestOption) (*key_manager.DecryptResponse, error)
}

// Wrapper encrypts and decrypts data using Scaleway Key Manager.
type Wrapper struct {
	accessKey       string
	secretKey       string
	credentialsFile string
	profile         string
	region          string
	projectId       string
	keyId           string
	apiUrl          string
	keyNotRequired  bool
	disallowEnvVars bool

	currentKeyId *atomic.Value
	client       KeyManagerAPI
}

var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new Scaleway Key Manager wrapper.
func NewWrapper() *Wrapper {
	w := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	w.currentKeyId.Store("")
	return w
}

// SetConfig configures the wrapper from options and environment variables.
//
// Order of precedence values:
// * Environment variable
// * Passed in config map
func (w *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	w.keyNotRequired = opts.withKeyNotRequired
	w.disallowEnvVars = opts.withDisallowEnvVars

	switch {
	case os.Getenv(EnvScalewayKmsWrapperKeyId) != "" && !opts.withDisallowEnvVars:
		w.keyId = os.Getenv(EnvScalewayKmsWrapperKeyId)
	case os.Getenv(EnvVaultScalewayKmsSealKeyId) != "" && !opts.withDisallowEnvVars:
		w.keyId = os.Getenv(EnvVaultScalewayKmsSealKeyId)
	case opts.WithKeyId != "":
		w.keyId = opts.WithKeyId
	case w.keyNotRequired:
		// key not required to set config
	default:
		return nil, fmt.Errorf("key id not found in env or config for scaleway kms wrapper configuration")
	}

	w.currentKeyId.Store(w.keyId)

	switch {
	case os.Getenv(EnvScalewayRegion) != "" && !opts.withDisallowEnvVars:
		w.region = os.Getenv(EnvScalewayRegion)
	case opts.withRegion != "":
		w.region = opts.withRegion
	default:
		return nil, errors.New("region not found in env or config for scaleway kms wrapper configuration")
	}

	switch {
	case os.Getenv(EnvScalewayProjectId) != "" && !opts.withDisallowEnvVars:
		w.projectId = os.Getenv(EnvScalewayProjectId)
	case opts.withProjectId != "":
		w.projectId = opts.withProjectId
	}

	w.credentialsFile = opts.withCredentialsFile
	w.profile = opts.withProfile
	if w.apiUrl == "" {
		w.apiUrl = opts.withAPIUrl
	}

	if w.credentialsFile == "" && w.profile == "" {
		switch {
		case os.Getenv(EnvScalewayAccessKey) != "" && !opts.withDisallowEnvVars:
			w.accessKey = os.Getenv(EnvScalewayAccessKey)
		case opts.withAccessKey != "":
			w.accessKey = opts.withAccessKey
		}
		switch {
		case os.Getenv(EnvScalewaySecretKey) != "" && !opts.withDisallowEnvVars:
			w.secretKey = os.Getenv(EnvScalewaySecretKey)
		case opts.withSecretKey != "":
			w.secretKey = opts.withSecretKey
		}
	}

	if w.client == nil {
		client, err := w.newKeyManagerClient()
		if err != nil {
			return nil, fmt.Errorf("error initializing scaleway key manager client: %w", err)
		}
		w.client = client
	}

	if !w.keyNotRequired {
		key, err := w.client.GetKey(&key_manager.GetKeyRequest{
			Region: scw.Region(w.region),
			KeyID:  w.keyId,
		}, scw.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("error fetching scaleway key manager key: %w", err)
		}
		if key.Usage == nil || key.Usage.SymmetricEncryption == nil {
			return nil, errors.New("key must have symmetric_encryption usage for vault auto-unseal")
		}
		if key.State != key_manager.KeyStateEnabled {
			return nil, fmt.Errorf("key must be in enabled state for vault auto-unseal, got %q", key.State)
		}
		w.currentKeyId.Store(key.ID)
	}

	wrapConfig := &wrapping.WrapperConfig{
		Metadata: map[string]string{
			"region":     w.region,
			"key_id":     w.keyId,
			"project_id": w.projectId,
		},
	}
	if w.apiUrl != "" {
		wrapConfig.Metadata["api_url"] = w.apiUrl
	}
	if w.credentialsFile != "" {
		wrapConfig.Metadata["credentials_file"] = w.credentialsFile
	}
	if w.profile != "" {
		wrapConfig.Metadata["profile"] = w.profile
	}

	return wrapConfig, nil
}

// Type returns the wrapper type identifier.
func (w *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeScalewayKms, nil
}

// KeyId returns the last known key id.
func (w *Wrapper) KeyId(_ context.Context) (string, error) {
	return w.currentKeyId.Load().(string), nil
}

// Encrypt encrypts plaintext using Scaleway Key Manager.
func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}
	if w.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	associatedData := associatedDataFromOpts(opts.WithAad)

	if opts.WithoutEnvelope {
		if len(plaintext) > maxDirectPlaintextSize {
			return nil, fmt.Errorf("plaintext size %d exceeds scaleway key manager limit of %d bytes for direct encryption", len(plaintext), maxDirectPlaintextSize)
		}

		resp, err := w.encryptWithKMS(ctx, plaintext, associatedData)
		if err != nil {
			return nil, fmt.Errorf("error encrypting data: %w", err)
		}

		w.currentKeyId.Store(resp.KeyID)

		return &wrapping.BlobInfo{
			Ciphertext: resp.Ciphertext,
			KeyInfo: &wrapping.KeyInfo{
				Mechanism: ScalewayKmsEncrypt,
				KeyId:     resp.KeyID,
			},
		}, nil
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	resp, err := w.encryptWithKMS(ctx, env.Key, associatedData)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data encryption key: %w", err)
	}

	w.currentKeyId.Store(resp.KeyID)

	return &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  ScalewayKmsEnvelopeAesGcmEncrypt,
			KeyId:      resp.KeyID,
			WrappedKey: resp.Ciphertext,
		},
	}, nil
}

// Decrypt decrypts a blob produced by Encrypt.
func (w *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}
	if in.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}
	if w.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	associatedData := associatedDataFromOpts(opts.WithAad)
	keyId := w.decryptKeyId(in)

	switch in.KeyInfo.Mechanism {
	case ScalewayKmsEncrypt:
		resp, err := w.client.Decrypt(&key_manager.DecryptRequest{
			Region:         scw.Region(w.region),
			KeyID:          keyId,
			Ciphertext:     in.Ciphertext,
			AssociatedData: associatedData,
		}, scw.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("error decrypting data: %w", err)
		}
		return resp.Plaintext, nil

	case ScalewayKmsEnvelopeAesGcmEncrypt:
		resp, err := w.client.Decrypt(&key_manager.DecryptRequest{
			Region:         scw.Region(w.region),
			KeyID:          keyId,
			Ciphertext:     in.KeyInfo.WrappedKey,
			AssociatedData: associatedData,
		}, scw.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
		}

		plaintext, err := wrapping.EnvelopeDecrypt(&wrapping.EnvelopeInfo{
			Key:        resp.Plaintext,
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

func (w *Wrapper) decryptKeyId(in *wrapping.BlobInfo) string {
	if in.KeyInfo != nil && in.KeyInfo.KeyId != "" {
		return in.KeyInfo.KeyId
	}
	return w.keyId
}

func associatedDataFromOpts(aad []byte) *[]byte {
	if len(aad) == 0 {
		return nil
	}
	return &aad
}

func (w *Wrapper) encryptWithKMS(ctx context.Context, plaintext []byte, associatedData *[]byte) (*key_manager.EncryptResponse, error) {
	return w.client.Encrypt(&key_manager.EncryptRequest{
		Region:         scw.Region(w.region),
		KeyID:          w.keyId,
		Plaintext:      plaintext,
		AssociatedData: associatedData,
	}, scw.WithContext(ctx))
}

func (w *Wrapper) newKeyManagerClient() (*key_manager.API, error) {
	clientOpts, err := w.authClientOptions()
	if err != nil {
		return nil, err
	}

	if w.projectId != "" {
		clientOpts = append(clientOpts, scw.WithDefaultProjectID(w.projectId))
	}
	if w.region != "" {
		clientOpts = append(clientOpts, scw.WithDefaultRegion(scw.Region(w.region)))
	}
	if w.apiUrl != "" {
		clientOpts = append(clientOpts, scw.WithAPIURL(w.apiUrl))
	}

	client, err := scw.NewClient(clientOpts...)
	if err != nil {
		return nil, err
	}

	return key_manager.NewAPI(client), nil
}

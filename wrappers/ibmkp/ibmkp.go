package ibmkp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	kp "github.com/IBM/keyprotect-go-client"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// These constants contain the accepted env vars
const (
	EnvIbmApiKey       = "IBMCLOUD_API_KEY"
	EnvIbmKpEndpoint   = "IBMCLOUD_KP_ENDPOINT"
	EnvIbmKpInstanceId = "IBMCLOUD_KP_INSTANCE_ID"
	EnvIbmKpKeyId      = "IBMCLOUD_KP_KEY_ID"
)

// Wrapper represents credentials and Key information for the KMS Key used to
// encryption and decryption
type Wrapper struct {
	apiKey     string
	endpoint   string
	instanceId string
	keyId      string

	keyNotRequired bool

	currentkeyId *atomic.Value

	client *kp.Client

	logger hclog.Logger
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new IBMKP wrapper with the provided options
func NewWrapper() *Wrapper {
	k := &Wrapper{
		currentkeyId: new(atomic.Value),
	}
	k.currentkeyId.Store("")
	return k
}

// SetConfig sets the fields on the Wrapper object based on
// values from the config parameter.
//
// Order of precedence IBM Key Protect values:
// * Environment variable
// * Passed in config map
func (k *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	k.keyNotRequired = opts.withKeyNotRequired
	k.logger = opts.withLogger

	// Check and set API Key
	switch {
	case os.Getenv(EnvIbmApiKey) != "" && !opts.withDisallowEnvVars:
		k.apiKey = os.Getenv(EnvIbmApiKey)
	case opts.withApiKey != "":
		k.apiKey = opts.withApiKey
	case k.keyNotRequired:
		// key not required to set config
	default:
		return nil, fmt.Errorf("'api_key' was not found in env or config for IBM Key Protect wrapper configuration")
	}

	// Check and set Endpoint
	switch {
	case os.Getenv(EnvIbmKpEndpoint) != "" && !opts.withDisallowEnvVars:
		k.endpoint = os.Getenv(EnvIbmKpEndpoint)
	case opts.withEndpoint != "":
		k.endpoint = opts.withEndpoint
	default:
		k.endpoint = kp.DefaultBaseURL
	}

	// Check and set instanceId
	switch {
	case os.Getenv(EnvIbmKpInstanceId) != "" && !opts.withDisallowEnvVars:
		k.instanceId = os.Getenv(EnvIbmKpInstanceId)
	case opts.withInstanceId != "":
		k.instanceId = opts.withInstanceId
	case k.keyNotRequired:
		// key not required to set config
	default:
		return nil, fmt.Errorf("'instance_id' was not found in env or config for IBM Key Protect wrapper configuration")
	}

	// Check and set keyId
	switch {
	case os.Getenv(EnvIbmKpKeyId) != "" && !opts.withDisallowEnvVars:
		k.keyId = os.Getenv(EnvIbmKpKeyId)
	case opts.WithKeyId != "":
		k.keyId = opts.WithKeyId
	default:
		return nil, fmt.Errorf("'key_id' was not found in env or config for IBM Key Protect wrapper configuration")
	}

	// Check and set k.client
	if k.client == nil {
		client, err := k.GetIbmKpClient()
		if err != nil {
			return nil, fmt.Errorf("error initializing IBM Key Protect wrapping client: %w", err)
		}

		if !k.keyNotRequired {
			// Test the client connection using provided key ID
			key, err := client.GetKeyMetadata(context.Background(), k.keyId)
			if err != nil {
				return nil, fmt.Errorf("error fetching IBM Key Protect wrapping key information: %w", err)
			}
			if key == nil || key.ID == "" {
				return nil, errors.New("no key information returned")
			}
			k.currentkeyId.Store(key.ID)
		}

		k.client = client
	}

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["endpoint"] = k.endpoint
	wrapConfig.Metadata["instance_id"] = k.instanceId
	wrapConfig.Metadata["key_id"] = k.keyId

	return wrapConfig, nil
}

// Type returns the wrapping type for this particular Wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeIbmKp, nil
}

// keyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.currentkeyId.Load().(string), nil
}

// Encrypt is used to encrypt the master key using the IBM KeyProtect API.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	if k.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	envelopeKeyBase64 := []byte(base64.StdEncoding.EncodeToString(env.Key))
	ciphertext, err := k.client.Wrap(ctx, k.keyId, envelopeKeyBase64, nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	k.currentkeyId.Store(k.keyId)

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      k.keyId,
			WrappedKey: ciphertext,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, errors.New("given input for decryption is nil")
	}

	if in.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}

	envelopeKeyBase64, err := k.client.Unwrap(ctx, in.KeyInfo.KeyId, in.KeyInfo.WrappedKey, nil)
	if err != nil {
		return nil, err
	}

	envelopeKey, err := base64.StdEncoding.DecodeString(string(envelopeKeyBase64))
	if err != nil {
		return nil, err
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        envelopeKey,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}

	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data with envelope: %w", err)
	}

	return plaintext, nil
}

// Client returns the IBM KP client used by the wrapper.
func (k *Wrapper) Client() *kp.Client {
	return k.client
}

func (k *Wrapper) getConfigAPIKey() kp.ClientConfig {
	return kp.ClientConfig{
		BaseURL:    k.endpoint,
		APIKey:     k.apiKey,
		TokenURL:   kp.DefaultTokenURL,
		InstanceID: k.instanceId,
		Verbose:    kp.VerboseFailOnly,
	}
}

// GetIbmKpClient returns an instance of the KMS client.
func (k *Wrapper) GetIbmKpClient() (*kp.Client, error) {
	options := k.getConfigAPIKey()
	api, err := kp.New(options, kp.DefaultTransport())
	if err != nil {
		return nil, err
	}

	return api, nil
}

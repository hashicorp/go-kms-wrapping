package ibmkp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	kp "github.com/IBM/keyprotect-go-client"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// These constants contain the accepted env vars
const (
	EnvIBMApiKey       = "IBMCLOUD_API_KEY"
	EnvIBMKPEndpoint   = "IBMCLOUD_KP_ENDPOINT"
	EnvIBMKPInstanceID = "IBMCLOUD_KP_INSTANCE_ID"
	EnvIBMKPKeyID      = "IBMCLOUD_KP_KEY_ID"
)

// Wrapper represents credentials and Key information for the KMS Key used to
// encryption and decryption
type Wrapper struct {
	endpoint   string
	apiKey     string
	instanceID string
	keyID      string

	currentKeyID *atomic.Value

	client *kp.Client
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new IBMKP wrapper with the provided options
func NewWrapper(opts *wrapping.WrapperOptions) *Wrapper {
	if opts == nil {
		opts = new(wrapping.WrapperOptions)
	}
	k := &Wrapper{
		currentKeyID: new(atomic.Value),
	}
	k.currentKeyID.Store("")
	return k
}

// SetConfig sets the fields on the Wrapper object based on
// values from the config parameter.
//
// Order of precedence IBM Key Protect values:
// * Environment variable
// * Value from Vault configuration file
func (k *Wrapper) SetConfig(config map[string]string) (map[string]string, error) {
	if config == nil {
		config = map[string]string{}
	}

	// Check and set API Key
	switch {
	case os.Getenv(EnvIBMApiKey) != "":
		k.apiKey = os.Getenv(EnvIBMApiKey)
	case config["api_key"] != "":
		k.apiKey = config["api_key"]
	default:
		return nil, fmt.Errorf("'api_key' was not found for IBM Key Protect wrapper configuration")
	}

	// Check and set Endpoint
	switch {
	case os.Getenv(EnvIBMKPEndpoint) != "":
		k.endpoint = os.Getenv(EnvIBMKPEndpoint)
	case config["endpoint"] != "":
		k.endpoint = config["endpoint"]
	default:
		k.endpoint = kp.DefaultBaseURL
	}

	// Check and set instanceID
	switch {
	case os.Getenv(EnvIBMKPInstanceID) != "":
		k.instanceID = os.Getenv(EnvIBMKPInstanceID)
	case config["instance_id"] != "":
		k.instanceID = config["instance_id"]
	default:
		return nil, fmt.Errorf("'instance_id' was not found for IBM Key Protect wrapper configuration")
	}

	// Check and set keyID
	switch {
	case os.Getenv(EnvIBMKPKeyID) != "":
		k.keyID = os.Getenv(EnvIBMKPKeyID)
	case config["key_id"] != "":
		k.keyID = config["key_id"]
	default:
		return nil, fmt.Errorf("'key_id' was not found for IBM Key Protect wrapper configuration")
	}

	// Check and set k.client
	if k.client == nil {
		client, err := k.GetIBMKPClient()
		if err != nil {
			return nil, fmt.Errorf("error initializing IBM Key Protect wrapping client: %w", err)
		}

		// Test the client connection using provided key ID
		key, err := client.GetKeyMetadata(context.Background(), k.keyID)
		if err != nil {
			return nil, fmt.Errorf("error fetching IBM Key Protect wrapping key information: %w", err)
		}
		if key == nil || key.ID == "" {
			return nil, errors.New("no key information returned")
		}
		k.currentKeyID.Store(key.ID)

		k.client = client
	}

	// Map that holds non-sensitive configuration info
	wrappingInfo := make(map[string]string)
	wrappingInfo["endpoint"] = k.endpoint
	wrappingInfo["instance_id"] = k.instanceID
	wrappingInfo["key_id"] = k.keyID

	return wrappingInfo, nil
}

// Init is called during core.Initialize. No-op at the moment.
func (k *Wrapper) Init(_ context.Context) error {
	return nil
}

// Finalize is called during shutdown. This is a no-op since
// Wrapper doesn't require any cleanup.
func (k *Wrapper) Finalize(_ context.Context) error {
	return nil
}

// Type returns the wrapping type for this particular Wrapper implementation
func (k *Wrapper) Type() string {
	return wrapping.IBMKP
}

// KeyID returns the last known key id
func (k *Wrapper) KeyID() string {
	return k.currentKeyID.Load().(string)
}

// HMACKeyID returns the last known HMAC key id
func (k *Wrapper) HMACKeyID() string {
	return ""
}

// Encrypt is used to encrypt the master key using the the AWS CMK.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(ctx context.Context, plaintext, aad []byte) (blob *wrapping.EncryptedBlobInfo, err error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	env, err := wrapping.NewEnvelope(nil).Encrypt(plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	if k.client == nil {
		return nil, fmt.Errorf("nil client")
	}

	envelopKeyBase64 := []byte(base64.StdEncoding.EncodeToString(env.Key))
	ciphertext, err := k.client.Wrap(ctx, k.keyID, envelopKeyBase64, nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	k.currentKeyID.Store(k.keyID)

	ret := &wrapping.EncryptedBlobInfo{
		Ciphertext: env.Ciphertext,
		IV:         env.IV,
		KeyInfo: &wrapping.KeyInfo{
			KeyID:      k.keyID,
			WrappedKey: ciphertext,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(ctx context.Context, in *wrapping.EncryptedBlobInfo, aad []byte) (pt []byte, err error) {
	if in == nil {
		return nil, errors.New("given input for decryption is nil")
	}

	if in.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}

	envelopKeyBase64, err := k.client.Unwrap(ctx, in.KeyInfo.KeyID, in.KeyInfo.WrappedKey, nil)
	if err != nil {
		return nil, err
	}

	envelopKey, err := base64.StdEncoding.DecodeString(string(envelopKeyBase64))
	if err != nil {
		return nil, err
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        envelopKey,
		IV:         in.IV,
		Ciphertext: in.Ciphertext,
	}

	plaintext, err := wrapping.NewEnvelope(nil).Decrypt(envInfo, aad)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data with envelope: %w", err)
	}

	return plaintext, nil
}

func (k *Wrapper) getConfigAPIKey() kp.ClientConfig {
	return kp.ClientConfig{
		BaseURL:    k.endpoint,
		APIKey:     k.apiKey,
		TokenURL:   kp.DefaultTokenURL,
		InstanceID: k.instanceID,
		Verbose:    kp.VerboseFailOnly,
	}
}

// GetIBMKPClient returns an instance of the KMS client.
func (k *Wrapper) GetIBMKPClient() (*kp.Client, error) {

	options := k.getConfigAPIKey()
	api, err := kp.New(options, kp.DefaultTransport())
	if err != nil {
		return nil, err
	}

	return api, nil

}

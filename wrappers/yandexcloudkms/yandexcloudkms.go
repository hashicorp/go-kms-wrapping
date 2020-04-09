package yandexcloudkms

import (
	"bytes"
	"context"
	"fmt"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	"github.com/yandex-cloud/go-sdk/iamkey"
	"io/ioutil"
	"os"
	"sync/atomic"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	ycsdk "github.com/yandex-cloud/go-sdk"
)

// These constants contain the accepted env vars
const (
	EnvYandexCloudOAuthToken = "YANDEXCLOUD_OAUTH_TOKEN"
	EnvYandexCloudKMSKeyID   = "YANDEXCLOUD_KMS_KEY_ID"
)

// Wrapper represents credentials and Key information for the KMS Key used to
// encryption and decryption
type Wrapper struct {
	client       kms.SymmetricCryptoServiceClient
	keyID        string
	currentKeyID *atomic.Value
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new Yandex.Cloud wrapper
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
// Order of precedence Yandex.Cloud values:
// * Environment variable
// * Value from Vault configuration file
// * Instance metadata role (access key and secret key)
// * Default values
func (k *Wrapper) SetConfig(config map[string]string) (map[string]string, error) {
	if config == nil {
		config = map[string]string{}
	}

	// Check and set KeyID
	switch {
	case os.Getenv(EnvYandexCloudKMSKeyID) != "":
		k.keyID = os.Getenv(EnvYandexCloudKMSKeyID)
	case config["kms_key_id"] != "":
		k.keyID = config["kms_key_id"]
	default:
		return nil, fmt.Errorf("'kms_key_id' not found for Yandex.Cloud wrapper configuration")
	}

	//// Please see GetRegion for an explanation of the order in which region is parsed.
	//var err error
	//k.region, err = awsutil.GetRegion(config["region"])
	//if err != nil {
	//	return nil, err
	//}

	//// Check and set AWS access key, secret key, and session token
	//k.accessKey = config["access_key"]
	//k.secretKey = config["secret_key"]
	//k.sessionToken = config["session_token"]
	//
	//k.endpoint = os.Getenv("AWS_KMS_ENDPOINT")
	//if k.endpoint == "" {
	//	if endpoint, ok := config["endpoint"]; ok {
	//		k.endpoint = endpoint
	//	}
	//}

	// Check and set k.client
	if k.client == nil {
		client, err := k.GetYandexCloudKMSClient(config)
		if err != nil {
			return nil, fmt.Errorf("error initializing Yandex.Cloud KMS wrapping client: %w", err)
		}

		plaintext := []byte("test")
		encryptResponse, err := client.Encrypt(
			context.Background(),
			&kms.SymmetricEncryptRequest{
				KeyId:     k.keyID,
				Plaintext: plaintext,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("encrypt error: %w", err)
		}
		decryptResponse, err := client.Decrypt(
			context.Background(),
			&kms.SymmetricDecryptRequest{
				KeyId:      k.keyID,
				Ciphertext: encryptResponse.Ciphertext,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("decrypt error: %w", err)
		}
		if !bytes.Equal(decryptResponse.Plaintext, plaintext) {
			return nil, fmt.Errorf("encrypt/decrypt error: %w", err)
		}

		//// Test the client connection using provided key ID
		//keyInfo, err := client.DescribeKey(&kms.DescribeKeyInput{
		//	KeyId: aws.String(k.keyID),
		//})
		//if err != nil {
		//	return nil, fmt.Errorf("error fetching AWS KMS wrapping key information: %w", err)
		//}
		//if keyInfo == nil || keyInfo.KeyMetadata == nil || keyInfo.KeyMetadata.KeyId == nil {
		//	return nil, errors.New("no key information returned")
		//}
		k.currentKeyID.Store(k.keyID)

		k.client = client
	}

	// Map that holds non-sensitive configuration info
	wrappingInfo := make(map[string]string)
	wrappingInfo["kms_key_id"] = k.keyID

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
	return wrapping.YandexCloudKMS
}

// KeyID returns the last known key id
func (k *Wrapper) KeyID() string {
	return k.currentKeyID.Load().(string)
}

// HMACKeyID returns the last known HMAC key id
func (k *Wrapper) HMACKeyID() string {
	return ""
}

// Encrypt is used to encrypt the master key using Yandex.Cloud symmetric key.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(_ context.Context, plaintext, aad []byte) (blob *wrapping.EncryptedBlobInfo, err error) {
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

	//input := &kms.EncryptInput{
	//	KeyId:     aws.String(k.keyID),
	//	Plaintext: env.Key,
	//}
	//output, err := k.client.Encrypt(input)
	//if err != nil {
	//	return nil, fmt.Errorf("error encrypting data: %w", err)
	//}

	encryptResponse, err := k.client.Encrypt(
		context.Background(),
		&kms.SymmetricEncryptRequest{
			KeyId:     k.keyID,
			Plaintext: env.Key,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	// Store the current key id
	//
	// When using a key alias, this will return the actual underlying key id
	// used for encryption.  This is helpful if you are looking to reencyrpt
	// your data when it is not using the latest key id. See these docs relating
	// to key rotation https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html
	keyID := encryptResponse.KeyId
	k.currentKeyID.Store(keyID)

	ret := &wrapping.EncryptedBlobInfo{
		Ciphertext: env.Ciphertext,
		IV:         env.IV,
		KeyInfo: &wrapping.KeyInfo{
			// Even though we do not use the key id during decryption, store it
			// to know exactly the specific key used in encryption in case we
			// want to rewrap older entries
			KeyID:      keyID,
			WrappedKey: encryptResponse.Ciphertext,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.EncryptedBlobInfo, aad []byte) (pt []byte, err error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	//// Default to mechanism used before key info was stored
	//if in.KeyInfo == nil {
	//	in.KeyInfo = &wrapping.KeyInfo{
	//		Mechanism: AWSKMSEncrypt,
	//	}
	//}

	//var plaintext []byte

	//// KeyID is not passed to this call because AWS handles this
	//// internally based on the metadata stored with the encrypted data
	//input := &kms.DecryptInput{
	//	CiphertextBlob: in.KeyInfo.WrappedKey,
	//}
	//output, err := k.client.Decrypt(input)
	//if err != nil {
	//	return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	//}

	decryptResponse, err := k.client.Decrypt(
		context.Background(),
		&kms.SymmetricDecryptRequest{
			KeyId:      k.keyID,
			Ciphertext: in.KeyInfo.WrappedKey,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        decryptResponse.Plaintext,
		IV:         in.IV,
		Ciphertext: in.Ciphertext,
	}
	plaintext, err := wrapping.NewEnvelope(nil).Decrypt(envInfo, aad)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

// GetYandexCloudKMSClient returns an instance of the KMS client.
func (k *Wrapper) GetYandexCloudKMSClient(config map[string]string) (kms.SymmetricCryptoServiceClient, error) {
	//credsConfig := &awsutil.CredentialsConfig{}
	//
	//credsConfig.AccessKey = k.accessKey
	//credsConfig.SecretKey = k.secretKey
	//credsConfig.SessionToken = k.sessionToken
	//credsConfig.Region = k.region
	//
	//credsConfig.HTTPClient = cleanhttp.DefaultClient()
	//
	//creds, err := credsConfig.GenerateCredentialChain()
	//if err != nil {
	//	return nil, err
	//}
	//
	//awsConfig := &aws.Config{
	//	Credentials: creds,
	//	Region:      aws.String(credsConfig.Region),
	//	HTTPClient:  cleanhttp.DefaultClient(),
	//}
	//
	//if k.endpoint != "" {
	//	awsConfig.Endpoint = aws.String(k.endpoint)
	//}
	//
	//sess, err := session.NewSession(awsConfig)
	//if err != nil {
	//	return nil, err
	//}

	/*
		var token string
		switch {
		case os.Getenv(EnvYandexCloudOAuthToken) != "":
			token = os.Getenv(EnvYandexCloudOAuthToken)
		case config["oauth_token"] != "":
			token = config["oauth_token"]
		default:
			return nil, fmt.Errorf("'oauth_token' not found for Yandex.Cloud wrapper configuration")
		}
		credentials := ycsdk.OAuthToken(token)
	*/

	content, err := ioutil.ReadFile("/Users/zamysel/private.key")
	if err != nil {
		return nil, err
	}
	credentials, err := ycsdk.ServiceAccountKey(&iamkey.Key{
		Id:         "ajep5qmhl8bgk7gpgfn7",
		Subject:    &iamkey.Key_ServiceAccountId{ServiceAccountId: "ajeu4tcraf114usctb77"},
		PrivateKey: string(content),
	})
	if err != nil {
		return nil, err
	}

	sdk, err := ycsdk.Build(
		context.Background(),
		ycsdk.Config{Credentials: credentials},
	)
	if err != nil {
		return nil, err
	}

	return sdk.KMSCrypto().SymmetricCrypto(), nil
}

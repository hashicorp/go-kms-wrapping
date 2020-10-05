package wrapping

import (
	"context"
	"crypto/rsa"

	"github.com/hashicorp/go-hclog"
)

// These values define known types of Wrappers
const (
	AEAD            = "aead"
	AliCloudKMS     = "alicloudkms"
	AWSKMS          = "awskms"
	AzureKeyVault   = "azurekeyvault"
	GCPCKMS         = "gcpckms"
	HuaweiCloudKMS  = "huaweicloudkms"
	MultiWrapper    = "multiwrapper"
	OCIKMS          = "ocikms"
	PKCS11          = "pkcs11"
	Shamir          = "shamir"
	TencentCloudKMS = "tencentcloudkms"
	Transit         = "transit"
	YandexCloudKMS  = "yandexcloudkms"
	Test            = "test-auto"

	// HSMAutoDeprecated is a deprecated type relevant to Vault prior to 0.9.0.
	// It is still referenced in certain code paths for upgrade purporses
	HSMAutoDeprecated = "hsm-auto"
)

// KeyType defines types of cryptographic keys.
type KeyType string

const (
	RSA2048 KeyType = "rsa_2048"
	RSA3072 KeyType = "rsa_3072"
	RSA4096 KeyType = "rsa_4096"
)

// Purpose defines the cryptographic capabilities of a key.
type Purpose string

const (
	Encrypt Purpose = "encrypt"
	Decrypt Purpose = "decrypt"
	Sign    Purpose = "sign"
	Verify  Purpose = "verify"
	Wrap    Purpose = "wrap"
	Unwrap  Purpose = "unwrap"
)

// ProtectionLevel defines where cryptographic operations are performed with a key.
type ProtectionLevel string

const (
	Software ProtectionLevel = "software"
	HSM      ProtectionLevel = "hsm"
)

// KMSKey represents a cryptographic key that can be imported into a KMS.
type KMSKey struct {
	Type            KeyType
	Purposes        []Purpose
	ProtectionLevel ProtectionLevel
	Material        KeyMaterial
}

// KeyMaterial contains key material for various key types.
type KeyMaterial struct {
	RSAKey *rsa.PrivateKey
}

// Wrapper is the embedded implementation of autoSeal that contains logic
// specific to encrypting and decrypting data, or in this case keys.
type Wrapper interface {
	// Type is the type of Wrapper
	Type() string

	// KeyID is the ID of the key currently used for encryption
	KeyID() string
	// HMACKeyID is the ID of the key currently used for HMACing (if any)
	HMACKeyID() string

	// Init allows performing any necessary setup calls before using this Wrapper
	Init(context.Context) error
	// Finalize should be called when all usage of this Wrapper is done
	Finalize(context.Context) error

	// Encrypt encrypts the given byte slice and puts information about the final result in the returned value. The second byte slice is to pass any additional authenticated data; this may or may not be used depending on the particular implementation.
	Encrypt(context.Context, []byte, []byte) (*EncryptedBlobInfo, error)
	// Decrypt takes in the value and decrypts it into the byte slice.  The byte slice is to pass any additional authenticated data; this may or may not be used depending on the particular implementation.
	Decrypt(context.Context, *EncryptedBlobInfo, []byte) ([]byte, error)
}

// LifecycleWrapper is a Wrapper that implements lifecycle management for keys in a KMS.
type LifecycleWrapper interface {
	Wrapper

	// ImportKey creates a named key by importing key material in the given KMSKey.
	// The key will have the given Type, Purpose, and ProtectionLevel if supported by the implementation.
	// Returns the ID of a new key version and an error.
	ImportKey(ctx context.Context, name string, key KMSKey) (string, error)

	// RotateKey rotates the named key by creating a new key version with key material in the given KMSKey.
	// The key version will have the given Type, Purpose, and ProtectionLevel if supported by the implementation.
	// Returns the ID of a new key version and an error.
	RotateKey(ctx context.Context, name string, key KMSKey) (string, error)

	// DeleteKey deletes the named key.
	// Returns a bool representing if the key exists and an error.
	DeleteKey(ctx context.Context, name string) (bool, error)

	// EnableKeyVersion enables the version of the named key.
	EnableKeyVersion(ctx context.Context, name, version string) error

	// DisableKeyVersion disables the version of the named key.
	DisableKeyVersion(ctx context.Context, name, version string) error
}

// WrapperOptions contains options used when creating a Wrapper
type WrapperOptions struct {
	Logger hclog.Logger

	// KeyNotRequired indicates if an existing key must be
	// supplied in the configuration for a Wrapper.
	KeyNotRequired bool
}

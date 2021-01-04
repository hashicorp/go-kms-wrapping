package azurekeyvault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/google/tink/go/kwp/subtle"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
)

const (
	EnvAzureKeyVaultWrapperVaultName = "AZUREKEYVAULT_WRAPPER_VAULT_NAME"
	EnvVaultAzureKeyVaultVaultName   = "VAULT_AZUREKEYVAULT_VAULT_NAME"

	EnvAzureKeyVaultWrapperKeyName = "AZUREKEYVAULT_WRAPPER_KEY_NAME"
	EnvVaultAzureKeyVaultKeyName   = "VAULT_AZUREKEYVAULT_KEY_NAME"
)

// Wrapper is an Wrapper that uses Azure Key Vault
// for crypto operations.  Azure Key Vault currently does not support
// keys that can encrypt long data (RSA keys).  Due to this fact, we generate
// and AES key and wrap the key using Key Vault and store it with the
// data
type Wrapper struct {
	tenantID     string
	clientID     string
	clientSecret string
	vaultName    string
	keyName      string

	currentKeyID *atomic.Value

	environment    azure.Environment
	client         *keyvault.BaseClient
	logger         hclog.Logger
	keyNotRequired bool
	baseURL        string
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new wrapper with the given options
func NewWrapper(opts *wrapping.WrapperOptions) *Wrapper {
	if opts == nil {
		opts = new(wrapping.WrapperOptions)
	}
	v := &Wrapper{
		currentKeyID:   new(atomic.Value),
		logger:         opts.Logger,
		keyNotRequired: opts.KeyNotRequired,
	}
	v.currentKeyID.Store("")
	return v
}

// SetConfig sets the fields on the Wrapper object based on
// values from the config parameter.
//
// Order of precedence:
// * Environment variable
// * Value from Vault configuration file
// * Managed Service Identity for instance
func (v *Wrapper) SetConfig(config map[string]string) (map[string]string, error) {
	if config == nil {
		config = map[string]string{}
	}

	switch {
	case os.Getenv("AZURE_TENANT_ID") != "":
		v.tenantID = os.Getenv("AZURE_TENANT_ID")
	case config["tenant_id"] != "":
		v.tenantID = config["tenant_id"]
	}

	switch {
	case os.Getenv("AZURE_CLIENT_ID") != "":
		v.clientID = os.Getenv("AZURE_CLIENT_ID")
	case config["client_id"] != "":
		v.clientID = config["client_id"]
	}

	switch {
	case os.Getenv("AZURE_CLIENT_SECRET") != "":
		v.clientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	case config["client_secret"] != "":
		v.clientSecret = config["client_secret"]
	}

	envName := os.Getenv("AZURE_ENVIRONMENT")
	if envName == "" {
		envName = config["environment"]
	}
	if envName == "" {
		v.environment = azure.PublicCloud
	} else {
		var err error
		v.environment, err = azure.EnvironmentFromName(envName)
		if err != nil {
			return nil, err
		}
	}

	switch {
	case os.Getenv(EnvAzureKeyVaultWrapperVaultName) != "":
		v.vaultName = os.Getenv(EnvAzureKeyVaultWrapperVaultName)
	case os.Getenv(EnvVaultAzureKeyVaultVaultName) != "":
		v.vaultName = os.Getenv(EnvVaultAzureKeyVaultVaultName)
	case config["vault_name"] != "":
		v.vaultName = config["vault_name"]
	default:
		return nil, errors.New("vault name is required")
	}

	switch {
	case os.Getenv(EnvAzureKeyVaultWrapperKeyName) != "":
		v.keyName = os.Getenv(EnvAzureKeyVaultWrapperKeyName)
	case os.Getenv(EnvVaultAzureKeyVaultKeyName) != "":
		v.keyName = os.Getenv(EnvVaultAzureKeyVaultKeyName)
	case config["key_name"] != "":
		v.keyName = config["key_name"]
	case v.keyNotRequired:
		// key not required to set config
	default:
		return nil, errors.New("key name is required")
	}

	// Set the base URL
	v.baseURL = v.buildBaseURL()

	if v.client == nil {
		client, err := v.getKeyVaultClient()
		if err != nil {
			return nil, fmt.Errorf("error initializing Azure Key Vault wrapper client: %w", err)
		}

		if !v.keyNotRequired {
			// Test the client connection using provided key ID
			keyInfo, err := client.GetKey(context.Background(), v.baseURL, v.keyName, "")
			if err != nil {
				return nil, fmt.Errorf("error fetching Azure Key Vault wrapper key information: %w", err)
			}
			if keyInfo.Key == nil {
				return nil, errors.New("no key information returned")
			}
			v.currentKeyID.Store(ParseKeyVersion(to.String(keyInfo.Key.Kid)))
		}

		v.client = client
	}

	// Map that holds non-sensitive configuration info
	wrapperInfo := make(map[string]string)
	wrapperInfo["environment"] = v.environment.Name
	wrapperInfo["vault_name"] = v.vaultName
	wrapperInfo["key_name"] = v.keyName

	return wrapperInfo, nil
}

// Init is called during core.Initialize.  This is a no-op.
func (v *Wrapper) Init(context.Context) error {
	return nil
}

// Finalize is called during shutdown. This is a no-op.
func (v *Wrapper) Finalize(context.Context) error {
	return nil
}

// Type returns the type for this particular Wrapper implementation
func (v *Wrapper) Type() string {
	return wrapping.AzureKeyVault
}

// KeyID returns the last known key id
func (v *Wrapper) KeyID() string {
	return v.currentKeyID.Load().(string)
}

// HMACKeyID returns the last known HMAC key id
func (v *Wrapper) HMACKeyID() string {
	return ""
}

// Encrypt is used to encrypt using Azure Key Vault.
// This returns the ciphertext, and/or any errors from this
// call.
func (v *Wrapper) Encrypt(ctx context.Context, plaintext, aad []byte) (blob *wrapping.EncryptedBlobInfo, err error) {
	if plaintext == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	env, err := wrapping.NewEnvelope(nil).Encrypt(plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("error wrapping dat: %w", err)
	}

	// Encrypt the DEK using Key Vault
	params := keyvault.KeyOperationsParameters{
		Algorithm: keyvault.RSAOAEP256,
		Value:     to.StringPtr(base64.URLEncoding.EncodeToString(env.Key)),
	}
	// Wrap key with the latest version for the key name
	resp, err := v.client.WrapKey(ctx, v.buildBaseURL(), v.keyName, "", params)
	if err != nil {
		return nil, err
	}

	// Store the current key version
	keyVersion := ParseKeyVersion(to.String(resp.Kid))
	v.currentKeyID.Store(keyVersion)

	ret := &wrapping.EncryptedBlobInfo{
		Ciphertext: env.Ciphertext,
		IV:         env.IV,
		KeyInfo: &wrapping.KeyInfo{
			KeyID:      keyVersion,
			WrappedKey: []byte(to.String(resp.Result)),
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext
func (v *Wrapper) Decrypt(ctx context.Context, in *wrapping.EncryptedBlobInfo, aad []byte) (pt []byte, err error) {
	if in == nil {
		return nil, errors.New("given input for decryption is nil")
	}

	if in.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}

	// Unwrap the key
	params := keyvault.KeyOperationsParameters{
		Algorithm: keyvault.RSAOAEP256,
		Value:     to.StringPtr(string(in.KeyInfo.WrappedKey)),
	}
	resp, err := v.client.UnwrapKey(ctx, v.buildBaseURL(), v.keyName, in.KeyInfo.KeyID, params)
	if err != nil {
		return nil, err
	}

	keyBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(to.String(resp.Result))
	if err != nil {
		return nil, err
	}
	envInfo := &wrapping.EnvelopeInfo{
		Key:        keyBytes,
		IV:         in.IV,
		Ciphertext: in.Ciphertext,
	}
	return wrapping.NewEnvelope(nil).Decrypt(envInfo, aad)
}

// ImportKey imports the given key into Azure Key Vault by implementing the
// Azure Key Vault bring your own key (BYOK) specification. The BYOK specification is
// detailed at https://docs.microsoft.com/en-us/azure/key-vault/keys/byok-specification.
func (v *Wrapper) ImportKey(ctx context.Context, name string, key wrapping.KMSKey) (string, error) {
	if err := v.validateKMSKey(key); err != nil {
		return "", err
	}

	// Generate a UUID for the name of the Key Exchange Key (KEK)
	kekName, err := uuid.GenerateUUID()
	if err != nil {
		return "", err
	}

	// Generate an HSM backed RSA key pair in Azure Key Vault.
	// This key will be used as the KEK and has an expiration.
	exp := date.UnixTime(time.Now().Add(3 * time.Minute))
	kekBundle, err := v.client.CreateKey(ctx, v.baseURL, kekName, keyvault.KeyCreateParameters{
		Kty:     keyvault.RSAHSM,
		KeySize: to.Int32Ptr(2048),
		KeyOps:  &[]keyvault.JSONWebKeyOperation{"import"},
		KeyAttributes: &keyvault.KeyAttributes{
			Expires: &exp,
		},
	})
	if err != nil || kekBundle.Key == nil {
		return "", fmt.Errorf("error generating KEK: %w", err)
	}
	defer func() {
		if _, err := v.client.DeleteKey(ctx, v.baseURL, kekName); err != nil {
			v.logger.Warn("error deleting KEK", "name", kekName, "error", err)
		}
	}()

	// Parse the RSA public key of the KEK
	kekPubKey, err := jwkToRSAPublicKey(kekBundle.Key)
	if err != nil {
		return "", err
	}

	// Produce the target key plaintext
	var targetKey []byte
	switch key.Type {
	case wrapping.RSA2048, wrapping.RSA3072, wrapping.RSA4096:
		// For an RSA key, the private key ASN.1 DER encoding [RFC3447] wrapped in PKCS#8 [RFC5208]
		if targetKey, err = x509.MarshalPKCS8PrivateKey(key.Material.RSAKey); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("%q does not support key type %q", v.Type(), key.Type)
	}

	// Produce the wrapped key material needed for import
	wrappedKeyMaterial, err := v.wrapTargetKey(kekPubKey, targetKey)
	if err != nil {
		return "", err
	}

	// Create the key transfer blob
	b := keyTransferBlob{
		SchemaVersion: "1.0.0",
		Header: keyTransferBlobHeader{
			Alg: "dir",
			Enc: "CKM_RSA_AES_KEY_WRAP",
			Kid: to.String(kekBundle.Key.Kid),
		},
		CipherText: wrappedKeyMaterial,
		Generator:  "HashiCorp",
	}
	ktb, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	ktbEncoded := base64.RawURLEncoding.EncodeToString(ktb)

	// Upload the key transfer blob to import the key
	kty := v.keyTypeToKty(key.Type)
	ops := v.keyPurposesToKeyOps(key.Purposes)
	imported, err := v.client.ImportKey(ctx, v.baseURL, name, keyvault.KeyImportParameters{
		Key: &keyvault.JSONWebKey{
			Kty:    kty,
			T:      to.StringPtr(ktbEncoded),
			KeyOps: to.StringSlicePtr(ops),
		},
	})
	if err != nil {
		return "", fmt.Errorf("error importing key: %w", err)
	}
	if imported.Key == nil || imported.Key.Kid == nil {
		return "", errors.New("imported key is missing identifier")
	}

	// Return the version ID generated for the imported key
	return ParseKeyVersion(to.String(imported.Key.Kid)), nil
}

// RotateKey rotates the key with the given name in Azure Key Vault. Rotating a
// key is achieved by importing the material in the given KMSKey into an existing
// key. After rotation, the current (latest) version of the key will contain the
// material in the given KMSKey.
func (v *Wrapper) RotateKey(ctx context.Context, name string, key wrapping.KMSKey) (string, error) {
	// Check that the key exists before importing a new version
	if _, err := v.client.GetKey(ctx, v.baseURL, name, ""); err != nil {
		return "", err
	}

	// Rotation works by importing key material into an existing key
	return v.ImportKey(ctx, name, key)
}

// DeleteKey deletes the key with the given name from Azure Key Vault. Deleting a key
// will result in the deletion of all versions of the key. After deletion, the key
// cannot be used for crypto operations.
func (v *Wrapper) DeleteKey(ctx context.Context, name string) (bool, error) {
	if res, err := v.client.DeleteKey(ctx, v.baseURL, name); err != nil {
		// The response isn't a pointer, but the embedded struct holding the status code is.
		// If we can't read the status code, assume the key exists and return the error.
		if res.Response.Response == nil {
			return true, err
		}

		// The key existed before the failed deletion attempt if the status code isn't a 404.
		return res.StatusCode != http.StatusNotFound, err
	}

	return true, nil
}

// EnableKeyVersion enables the given version of the given key.
func (v *Wrapper) EnableKeyVersion(ctx context.Context, name, version string) error {
	_, err := v.client.UpdateKey(ctx, v.baseURL, name, version, keyvault.KeyUpdateParameters{
		KeyAttributes: &keyvault.KeyAttributes{
			Enabled: to.BoolPtr(true),
		},
	})
	return err
}

// DisableKeyVersion disables the given version of the given key.
func (v *Wrapper) DisableKeyVersion(ctx context.Context, name, version string) error {
	_, err := v.client.UpdateKey(ctx, v.baseURL, name, version, keyvault.KeyUpdateParameters{
		KeyAttributes: &keyvault.KeyAttributes{
			Enabled: to.BoolPtr(false),
		},
	})
	return err
}

// keyTransferBlob represents the structure of a key transfer blob
// used to import a key into Azure Key Vault. The format of the key
// transfer blob uses JSON Web Encryption compact serialization [RFC7516]
// primarily as a vehicle for delivering the required metadata to the
// service for correct decryption.
type keyTransferBlob struct {
	SchemaVersion string                `json:"schema_version"`
	Header        keyTransferBlobHeader `json:"header"`
	CipherText    string                `json:"ciphertext"`
	Generator     string                `json:"generator"`
}

// keyTransferBlobHeader represents the header of a key transfer blob.
type keyTransferBlobHeader struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Enc string `json:"enc"`
}

// jwkToRSAPublicKey returns a pointer to an rsa.PublicKey that contains
// the modulus and public exponent from the given keyvault.JSONWebKey (JWK).
// Both the RSA modulus "N" and public exponent "E" in the JWK are
// parsed as the base64url encoding of the value's unsigned big-endian
// representation as an octet sequence. For more details, see
// https://tools.ietf.org/html/rfc7518#section-6.3.1
func jwkToRSAPublicKey(jwk *keyvault.JSONWebKey) (*rsa.PublicKey, error) {
	if jwk == nil || jwk.N == nil || jwk.E == nil {
		return nil, fmt.Errorf("must provide an RSA type JSONWebKey")
	}

	// Decode the RSA modulus
	base64N := to.String(jwk.N)
	nd, err := base64.RawURLEncoding.DecodeString(base64N)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nd)

	// Decode the RSA public exponent
	base64E := to.String(jwk.E)
	ed, err := base64.RawURLEncoding.DecodeString(base64E)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(ed)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Uint64()),
	}, nil
}

// wrapTargetKey returns wrapped key material according to the steps outlined in
// the Azure Key Vault BYOK specification. For details, see the specification at
// https://docs.microsoft.com/en-us/azure/key-vault/keys/byok-specification#key-transfer-blob.
//
// More specific details related to the wrapping and unwrapping mechanism used can be found at
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908.
func (v *Wrapper) wrapTargetKey(pub *rsa.PublicKey, targetKey []byte) (string, error) {
	// Generate an ephemeral AES key
	aesKey, err := uuid.GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}

	// Wrap the AES key with the RSA public key using RSA-OAEP with SHA1
	aesKeyWrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, aesKey, []byte{})
	if err != nil {
		return "", err
	}

	// Wrap the target key plaintext using AES Key Wrap with Padding [RFC5649]
	kwp, err := subtle.NewKWP(aesKey)
	if err != nil {
		return "", err
	}
	wrappedTargetKey, err := kwp.Wrap(targetKey)
	if err != nil {
		return "", err
	}

	// Zero the memory of the ephemeral AES key. This is a best-effort
	// cleanup, as the buffer may have been copied during a garbage
	// collection. Exposure of the key in memory is minimized by
	// zeroing the buffer as soon as it's no longer needed.
	for i := range aesKey {
		aesKey[i] = 0
	}

	// Concatenate the wrapped AES key and the wrapped target
	// key to produce the final ciphertext
	wrappedKeyMaterial := append(aesKeyWrapped, wrappedTargetKey...)

	// Return a base64 URL encoding of the ciphertext
	return base64.RawURLEncoding.EncodeToString(wrappedKeyMaterial), nil
}

// validateKMSKey validates the given KSMKey with respect to the limitations of Azure Key Vault.
func (v *Wrapper) validateKMSKey(key wrapping.KMSKey) error {
	// Validate the key type and material
	switch key.Type {
	case wrapping.RSA2048, wrapping.RSA3072, wrapping.RSA4096:
		if key.Material.RSAKey == nil {
			return fmt.Errorf("must provide RSA key for key type %q", key.Type)
		}
	default:
		return fmt.Errorf("%q does not support key type %q", v.Type(), key.Type)
	}

	// Validate the key purpose
	if len(key.Purposes) == 0 {
		return errors.New("key must have at least one purpose")
	}
	for _, p := range key.Purposes {
		switch p {
		case wrapping.Encrypt, wrapping.Decrypt, wrapping.Sign,
			wrapping.Verify, wrapping.Wrap, wrapping.Unwrap:
		default:
			return fmt.Errorf("%q does not support key purpose %q", v.Type(), p)
		}
	}

	// Validate the key protection level
	switch key.ProtectionLevel {
	case wrapping.HSM:
	default:
		return fmt.Errorf("%q does not support key protection level %q", v.Type(), key.ProtectionLevel)
	}

	return nil
}

// keyPurposesToKeyOps translates a slice of wrapping.Purpose values
// into a slice of JSON Web Key (JWK) [RFC7517] key_ops. For details,
// see https://tools.ietf.org/html/rfc7517#section-4.3.
func (v *Wrapper) keyPurposesToKeyOps(purposes []wrapping.Purpose) []string {
	ops := make([]string, 0)
	for _, p := range purposes {
		switch p {
		case wrapping.Encrypt:
			ops = append(ops, "encrypt")
		case wrapping.Decrypt:
			ops = append(ops, "decrypt")
		case wrapping.Sign:
			ops = append(ops, "sign")
		case wrapping.Verify:
			ops = append(ops, "verify")
		case wrapping.Wrap:
			ops = append(ops, "wrapKey")
		case wrapping.Unwrap:
			ops = append(ops, "unwrapKey")
		}
	}
	return ops
}

// keyTypeToKty translates the given wrapping.KeyType to a its equivalent keyvault.JSONWebKeyType.
func (v *Wrapper) keyTypeToKty(kt wrapping.KeyType) keyvault.JSONWebKeyType {
	switch kt {
	case wrapping.RSA2048, wrapping.RSA3072, wrapping.RSA4096:
		// Keys can only be imported with HSM protection,
		// so HSM variants of the key type are returned.
		return keyvault.RSAHSM
	}
	return ""
}

func (v *Wrapper) buildBaseURL() string {
	return fmt.Sprintf("https://%s.%s/", v.vaultName, v.environment.KeyVaultDNSSuffix)
}

func (v *Wrapper) getKeyVaultClient() (*keyvault.BaseClient, error) {
	var authorizer autorest.Authorizer
	var err error

	switch {
	case v.clientID != "" && v.clientSecret != "":
		config := auth.NewClientCredentialsConfig(v.clientID, v.clientSecret, v.tenantID)
		config.AADEndpoint = v.environment.ActiveDirectoryEndpoint
		config.Resource = strings.TrimSuffix(v.environment.KeyVaultEndpoint, "/")
		authorizer, err = config.Authorizer()
		if err != nil {
			return nil, err
		}
	// By default use MSI
	default:
		config := auth.NewMSIConfig()
		config.Resource = strings.TrimSuffix(v.environment.KeyVaultEndpoint, "/")
		authorizer, err = config.Authorizer()
		if err != nil {
			return nil, err
		}
	}

	client := keyvault.New()
	client.Authorizer = authorizer
	return &client, nil
}

func (v *Wrapper) VaultName() string {
	return v.vaultName
}

func (v *Wrapper) Client() *keyvault.BaseClient {
	return v.client
}

func (v *Wrapper) Environment() azure.Environment {
	return v.environment
}

func (v *Wrapper) Logger() hclog.Logger {
	return v.logger
}

// Kid gets returned as a full URL, get the last bit which is just
// the version
func ParseKeyVersion(kid string) string {
	keyVersionParts := strings.Split(kid, "/")
	return keyVersionParts[len(keyVersionParts)-1]
}

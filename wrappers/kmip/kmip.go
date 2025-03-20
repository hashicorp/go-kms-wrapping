// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// Initially inspired and adapted from ceph's internal kmip package
// https://github.com/ceph/ceph-csi/blob/devel/internal/kms/kmip.go

package kmip

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/ttlv"
)

// These constants contain the accepted env vars; the Vault one is for backwards compat
const (
	EnvKmipWrapperKeyId   = "BAO_KMIP_WRAPPER_KEY_ID"
	EnvVaultKmipSealKeyId = "VAULT_KMIP_SEAL_KEY_ID"

	EnvKmipEndpoint     = "BAO_KMIP_ENDPOINT"
	EnvKmipCaCert       = "BAO_KMIP_CA_CERT"
	EnvKmipClientCert   = "BAO_KMIP_CLIENT_CERT"
	EnvKmipClientKey    = "BAO_KMIP_CLIENT_KEY"
	EnvKmipServerName   = "BAO_KMIP_SERVER_NAME"
	EnvKmipTimeout      = "BAO_KMIP_TIMEOUT"
	EnvKmipEncryptAlg   = "BAO_KMIP_ENCRYPT_ALG"
	EnvKmipTls12Ciphers = "BAO_KMIP_TLS12_CIPHERS"
)

var (
	// Preset kmip cryptographic parameters that can be selected from config
	cryptoParamsPreset = map[string]kmip.CryptographicParameters{
		"AES_GCM": {
			CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
			BlockCipherMode:        kmip.BlockCipherModeGCM,
			TagLength:              16,
			IVLength:               12,
		},
		"RSA_OAEP_SHA256": {
			CryptographicAlgorithm:        kmip.CryptographicAlgorithmRSA,
			PaddingMethod:                 kmip.PaddingMethodOAEP,
			HashingAlgorithm:              kmip.HashingAlgorithmSHA_256,
			MaskGenerator:                 kmip.MaskGeneratorMGF1,
			MaskGeneratorHashingAlgorithm: kmip.HashingAlgorithmSHA_256,
		},
		"RSA_OAEP_SHA384": {
			CryptographicAlgorithm:        kmip.CryptographicAlgorithmRSA,
			PaddingMethod:                 kmip.PaddingMethodOAEP,
			HashingAlgorithm:              kmip.HashingAlgorithmSHA_384,
			MaskGenerator:                 kmip.MaskGeneratorMGF1,
			MaskGeneratorHashingAlgorithm: kmip.HashingAlgorithmSHA_384,
		},
		"RSA_OAEP_SHA512": {
			CryptographicAlgorithm:        kmip.CryptographicAlgorithmRSA,
			PaddingMethod:                 kmip.PaddingMethodOAEP,
			HashingAlgorithm:              kmip.HashingAlgorithmSHA_512,
			MaskGenerator:                 kmip.MaskGeneratorMGF1,
			MaskGeneratorHashingAlgorithm: kmip.HashingAlgorithmSHA_512,
		},
	}

	// Map between crypto param name, and mechanism ID. The ID is saved with the wrapped key
	// so we can use the same for decryption. This allows changing the cryptographic parameter for the next encryption.
	mechanisms = []string{"AES_GCM", "RSA_OAEP_SHA256", "RSA_OAEP_SHA384", "RSA_OAEP_SHA512"}
)

// Wrapper is a Wrapper that uses KMIP
type Wrapper struct {
	// keyId is the private key or symmetric key ID.
	keyId string
	// pubKeyId is used for asymmetric encryption.
	// It's automatically discovered and set during initialization.
	// It's left empty when using a symmetric key / algorithm.
	pubKeyId     string
	endpoint     string
	timeout      uint64
	opts         []kmipclient.Option
	cryptoParams kmip.CryptographicParameters
	// This is a id saved into the encrypted payload next to the decryption key ID so we can reuse the same
	// algorithm for decryption that was used for encryption. This allows for changing the algorithm while keeping
	// the capability to decrypt previously encrypted values.
	mechanismID uint64
	// cachedClient is a closed kmip connection that can be reopened.
	// It will reuse initial connection parameters and protocol version
	// negociated the first time. This avoids useless version negociations on subsequent connections.
	cachedClient *kmipclient.Client
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new KMIP Wrapper
func NewWrapper() *Wrapper {
	return &Wrapper{}
}

// SetConfig sets the fields on the KmipWrapper object based on
// values from the config parameter.
//
// Order of precedence Kmip values:
// * Environment variable
// * Value from Vault configuration file
// * Instance metadata role (access key and secret key)
func (k *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Check and set KeyId
	switch {
	case os.Getenv(EnvKmipWrapperKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyId = os.Getenv(EnvKmipWrapperKeyId)
	case os.Getenv(EnvVaultKmipSealKeyId) != "" && !opts.Options.WithDisallowEnvVars:
		k.keyId = os.Getenv(EnvVaultKmipSealKeyId)
	case opts.WithKeyId != "":
		k.keyId = opts.WithKeyId
	default:
		return nil, fmt.Errorf("key id not found (env or config) for kmip wrapper configuration")
	}

	// Uncomment this line to enable tracing of KMIP requests and responses
	// k.opts = append(k.opts, kmipclient.WithMiddlewares(kmipclient.DebugMiddleware(os.Stderr, ttlv.MarshalXML)))

	// Set and check k.client
	if !opts.Options.WithDisallowEnvVars {
		k.endpoint = os.Getenv(EnvKmipEndpoint)
	}
	if k.endpoint == "" {
		k.endpoint = opts.withEndpoint
	}

	caCertFile := ""
	if !opts.Options.WithDisallowEnvVars {
		caCertFile = os.Getenv(EnvKmipCaCert)
	}
	if caCertFile == "" {
		caCertFile = opts.withCaCert
	}
	k.opts = append(k.opts, kmipclient.WithRootCAFile(caCertFile))

	clientCertFile := ""
	if !opts.Options.WithDisallowEnvVars {
		clientCertFile = os.Getenv(EnvKmipClientCert)
	}
	if clientCertFile == "" {
		clientCertFile = opts.withClientCert
	}

	clientKeyFile := ""
	if !opts.Options.WithDisallowEnvVars {
		clientKeyFile = os.Getenv(EnvKmipClientKey)
	}
	if clientKeyFile == "" {
		clientKeyFile = opts.withClientKey
	}

	if clientKeyFile != "" || clientCertFile != "" {
		k.opts = append(k.opts, kmipclient.WithClientCertFiles(clientCertFile, clientKeyFile))
	}

	serverName := ""
	if !opts.Options.WithDisallowEnvVars {
		serverName = os.Getenv(EnvKmipServerName)
	}
	if serverName == "" {
		serverName = opts.withServerName
	}
	if serverName != "" {
		k.opts = append(k.opts, kmipclient.WithServerName(serverName))
	}

	if !opts.Options.WithDisallowEnvVars {
		timeoutString := os.Getenv(EnvKmipTimeout)
		timeout := uint64(0)
		if timeoutString != "" {
			var err error
			timeout, err = strconv.ParseUint(timeoutString, 10, 64)
			if err != nil {
				return nil, err
			}
		}
		k.timeout = timeout
	}
	if k.timeout == 0 {
		k.timeout = opts.withTimeout
	}

	if k.timeout > 0 {
		k.opts = append(k.opts, kmipclient.WithMiddlewares(
			kmipclient.TimeoutMiddleware(time.Duration(k.timeout)*time.Second),
		))
	}

	ciphers := []string{}
	if !opts.Options.WithDisallowEnvVars {
		cipherStr := os.Getenv(EnvKmipTls12Ciphers)
		if cipherStr != "" {
			ciphers = strings.Split(cipherStr, ",")
		}
	}
	if len(ciphers) == 0 {
		ciphers = opts.withTls12Ciphers
	}
	if len(ciphers) > 0 {
		k.opts = append(k.opts, kmipclient.WithTlsCipherSuiteNames(ciphers...))
	}

	cpname := ""
	if !opts.Options.WithDisallowEnvVars {
		cpname = os.Getenv(EnvKmipEncryptAlg)
	}
	if cpname == "" {
		cpname = opts.withCryptoParams
	}
	var ok bool
	k.cryptoParams, ok = cryptoParamsPreset[cpname]
	if !ok {
		return nil, fmt.Errorf("invalid crypto parameters %q", cpname)
	}
	mId := slices.Index(mechanisms, cpname)
	if mId < 0 {
		return nil, fmt.Errorf("KMIP cryptographic parameter does not have an associated mechanism ID")
	}
	k.mechanismID = uint64(mId)

	// Encrypt / Decrypt operations support has been added in kmip v1.2. So we cannot support v1.0 nor v1.1
	k.opts = append(k.opts, kmipclient.WithKmipVersions(kmip.V1_2, kmip.V1_3, kmip.V1_4))

	conn, err := k.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to dial kmip connection endpoint: %w", err)
	}
	defer conn.Close()

	if err := k.verifyKey(ctx, conn); err != nil {
		return nil, fmt.Errorf("invalid kmip key object: %w", err)
	}

	// Cache client so we can clone it to reopen it on demand, skipping protocol version negociation
	k.cachedClient = conn

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["kms_key_id"] = k.keyId
	wrapConfig.Metadata["endpoint"] = k.endpoint
	wrapConfig.Metadata["timeout"] = strconv.Itoa(int(k.timeout))
	wrapConfig.Metadata["encrypt_alg"] = cpname
	wrapConfig.Metadata["kmip_version"] = conn.Version().String()
	if serverName != "" {
		wrapConfig.Metadata["server_name"] = serverName
	}
	if len(ciphers) != 0 {
		wrapConfig.Metadata["kmip_tls12_ciphers"] = strings.Join(ciphers, ",")
	}
	if k.pubKeyId != "" {
		wrapConfig.Metadata["kms_public_key_id"] = k.pubKeyId
	}

	return wrapConfig, nil
}

// Type returns the type for this particular wrapper implementation
func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeKmip, nil
}

// KeyId returns the last known key id
func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.keyId, nil
}

// Encrypt is used to encrypt the master key using the the KMIP.
// This returns the ciphertext, and/or any errors from this
// call. This should be called after the KMS client has been instantiated.
func (k *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("given plaintext for encryption is nil")
	}

	ciphertext, nonce, err := k.encryptKMIP(ctx, plaintext)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	ret := &wrapping.BlobInfo{
		Ciphertext: ciphertext,
		Iv:         nonce,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:     k.keyId, // This is the decryption key ID (ie: the AES key or the RSA private key)
			Mechanism: k.mechanismID,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext. This should be called after Init.
func (k *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, fmt.Errorf("given input for decryption is nil")
	}

	mId := in.KeyInfo.Mechanism
	if mId >= uint64(len(mechanisms)) {
		return nil, fmt.Errorf("invalid encryption mechanism ID %q", mId)
	}
	cparams, ok := cryptoParamsPreset[mechanisms[mId]]
	if !ok {
		return nil, fmt.Errorf("mechanism ID does not match any KMIP cryptographic parameter")
	}

	plaintext, err := k.decryptKMIP(ctx, in.KeyInfo.KeyId, cparams, in.Iv, in.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data encryption key: %w", err)
	}

	return plaintext, nil
}

// encryptKMIP uses the KMIP encrypt operation to encrypt the DEK.
func (kms *Wrapper) encryptKMIP(ctx context.Context, plainDEK []byte) ([]byte, []byte, error) {
	var iv []byte
	var err error
	if ivl := kms.cryptoParams.IVLength; ivl > 0 {
		iv, err = uuid.GenerateRandomBytes(int(ivl))
		if err != nil {
			return nil, nil, err
		}
	}

	client, err := kms.connect(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	keyId := kms.keyId

	// When using RSA, some KMIP servers may accept encryption using the private key ID, some others only accept the public key ID.
	// Let's play it safe and always use the public key for encryption.
	// The public key id is looked-up during initialization. It's empty when running in symmetric mode.
	if kms.pubKeyId != "" {
		keyId = kms.pubKeyId
	}

	encryptRespPayload, err := client.Encrypt(keyId).
		WithIvCounterNonce(iv).
		WithCryptographicParameters(kms.cryptoParams).
		Data(plainDEK).
		ExecContext(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Append the encryption tag (if any) to the ciphertext. Depending on the KMIP version and the implementation,
	// sometimes the tag is already appended to th cipher text, sometimes it's in the AuthenticatedEncryptionTag field.
	// When using RSA-OAEP, this is a NOOP as AuthenticatedEncryptionTag is empty.
	ciphertext := append(encryptRespPayload.Data, encryptRespPayload.AuthenticatedEncryptionTag...)
	return ciphertext, iv, nil
}

// decryptKMIP uses the KMIP decrypt operation  to decrypt the DEK.
func (kms *Wrapper) decryptKMIP(ctx context.Context, keyId string, cparams kmip.CryptographicParameters, nonce, encryptedDEK []byte) ([]byte, error) {
	tagLen := int(kms.cryptoParams.TagLength)
	if len(encryptedDEK) < tagLen {
		return nil, errors.New("invalid encrypted DEK")
	}

	client, err := kms.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	reqBuilder := client.Decrypt(keyId).
		WithIvCounterNonce(nonce).
		WithCryptographicParameters(cparams)

	// Starting from kmip 1.4, GCM authentication tag is handled separately
	// in a dedicated field. Prior 1.4, it's appended at the end of the ciphertext.
	// (In reality, it mainly depends on the vendors)
	if tagLen > 0 && ttlv.CompareVersions(client.Version(), kmip.V1_4) >= 0 {
		reqBuilder = reqBuilder.WithAuthTag(encryptedDEK[len(encryptedDEK)-tagLen:])
		encryptedDEK = encryptedDEK[:len(encryptedDEK)-tagLen]
	}

	decryptRespPayload, err := reqBuilder.
		Data(encryptedDEK).
		ExecContext(ctx)
	if err != nil {
		return nil, err
	}

	return decryptRespPayload.Data, nil
}

// connect to the kmip endpoint, perform TLS and KMIP handshakes.
func (kms *Wrapper) connect(ctx context.Context) (*kmipclient.Client, error) {
	var conn *kmipclient.Client
	var err error
	if kms.cachedClient != nil {
		// Cloning the cached client establish a new connection, reusing previously set parameters.
		// It also skips protocol version negociation, reusing previously negociated version.
		conn, err = kms.cachedClient.CloneCtx(ctx)
	} else {
		conn, err = kmipclient.DialContext(ctx, kms.endpoint, kms.opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to dial kmip connection endpoint: %w", err)
	}
	return conn, nil
}

// verifyKey checks that the key has the properties / attributes needed to perform
// the configured encryption & decryption. In case a asymmetric algorithm, it will lookup
// and checks the public key, then save its id to be used during encryption.
func (kms *Wrapper) verifyKey(ctx context.Context, client *kmipclient.Client) error {
	var expectedObjectType kmip.ObjectType
	alg := kms.cryptoParams.CryptographicAlgorithm
	switch alg {
	case kmip.CryptographicAlgorithmRSA:
		expectedObjectType = kmip.ObjectTypePrivateKey
	case kmip.CryptographicAlgorithmAES:
		expectedObjectType = kmip.ObjectTypeSymmetricKey
	default:
		return fmt.Errorf("unsupported cryptographic algorithm %q", ttlv.EnumStr(alg))
	}
	pubKey, err := verifyKeyAttributes(ctx, client, kms.keyId, alg, expectedObjectType)
	if err != nil {
		return err
	}

	if pubKey != "" {
		if _, err = verifyKeyAttributes(ctx, client, pubKey, alg, kmip.ObjectTypePublicKey); err != nil {
			return err
		}
		kms.pubKeyId = pubKey
	}
	return nil
}

// verifyAttributes ensures that the key with id `keyId` has the expected atributes tor perform encryption and/or decryption
// using the algorithm specified by `alg`.
//
// It checks the following attributes:
//   - The object type
//   - The cryptographic algorithm
//   - The cryptographic usage
//   - The public key link when keyId is a private key
//
// The public key id is returned when keyId matches a private key, otherwise the returned public key id is empty.
func verifyKeyAttributes(ctx context.Context, client *kmipclient.Client, keyId string, alg kmip.CryptographicAlgorithm, expectedObjectType kmip.ObjectType) (string, error) {
	resp, err := client.GetAttributes(keyId,
		kmip.AttributeNameObjectType,
		kmip.AttributeNameCryptographicAlgorithm,
		kmip.AttributeNameCryptographicUsageMask,
		kmip.AttributeNameLink,
	).ExecContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get key attributes: %w", err)
	}
	pubKeyId := ""
	for _, attr := range resp.Attribute {
		switch attr.AttributeName {
		case kmip.AttributeNameCryptographicAlgorithm:
			keyAlg := attr.AttributeValue.(kmip.CryptographicAlgorithm)
			if alg != keyAlg {
				return "", fmt.Errorf("key has an invalid cryptographic algorithm attribute (wants %q, got %q)", ttlv.EnumStr(alg), ttlv.EnumStr(keyAlg))
			}
		case kmip.AttributeNameObjectType:
			otype := attr.AttributeValue.(kmip.ObjectType)
			if expectedObjectType != otype {
				return "", fmt.Errorf("unexpected object type (wants %q, got %q)", ttlv.EnumStr(expectedObjectType), ttlv.EnumStr(otype))
			}
		case kmip.AttributeNameCryptographicUsageMask:
			mask := attr.AttributeValue.(kmip.CryptographicUsageMask)
			if (expectedObjectType == kmip.ObjectTypeSymmetricKey || expectedObjectType == kmip.ObjectTypePrivateKey) && mask&kmip.CryptographicUsageDecrypt == 0 {
				return "", fmt.Errorf("key %q does not allow decrypt operations", keyId)
			}
			if (expectedObjectType == kmip.ObjectTypeSymmetricKey || expectedObjectType == kmip.ObjectTypePublicKey) && mask&kmip.CryptographicUsageEncrypt == 0 {
				return "", fmt.Errorf("key %q does not allow encrypt operations", keyId)
			}
		case kmip.AttributeNameLink:
			if expectedObjectType != kmip.ObjectTypePrivateKey {
				continue
			}
			link, ok := attr.AttributeValue.(kmip.Link)
			if ok && link.LinkType == kmip.LinkTypePublicKeyLink {
				pubKeyId = link.LinkedObjectIdentifier
			}
		}
	}
	if expectedObjectType == kmip.ObjectTypePrivateKey {
		if pubKeyId == "" {
			return "", fmt.Errorf("missing public key link attribute for the private key %q", keyId)
		}
	}
	return pubKeyId, nil
}

package aead

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	"golang.org/x/crypto/hkdf"
)

// Wrapper implements the wrapping.Wrapper interface for AEAD
type Wrapper struct {
	keyId    string
	keyBytes []byte
	aead     cipher.AEAD
}

// ShamirWrapper is here for backwards compatibility for Vault; it reports a
// type of "shamir" instead of "aead"
type ShamirWrapper struct {
	*Wrapper
}

// Ensure that we are implementing Wrapper
var (
	_ wrapping.Wrapper = (*Wrapper)(nil)
	_ wrapping.Wrapper = (*ShamirWrapper)(nil)
)

// NewWrapper creates a new Wrapper with the provided logger. No options are
// supported.
func NewWrapper() *Wrapper {
	seal := new(Wrapper)
	return seal
}

// Deprecated: NewShamirWrapper returns a type of "shamir" instead of "aead" and
// is for backwards compatibility with old versions of Vault. Do not use in new
// code.
func NewShamirWrapper() *ShamirWrapper {
	return &ShamirWrapper{
		Wrapper: NewWrapper(),
	}
}

// NewDerivedWrapper returns an aead.Wrapper whose key is set to an hkdf-based
// derivation from the original wrapper
//
// Supported options:
//
// * wrapping.WithKeyId: The key ID, if any, to set on the derived wrapper
//
// * wrapping.WithWrapperOptions: A struct containing the following:
//
// ** "aead_type": The type of AEAD to use as a string, defaults to
// wrapping.AeadTypeAesGcm.String()
//
// ** "hash": The type of hash function to use for derivation as a string,
// defaults to wrapping.HashTypeSha256.String()
//
// ** "info": The info value, if any, to use in the derivation, as a
// base64-encoded byte slice
//
// ** "salt": The salt value, if any, to use in the derivation, as a
// base64-encoded byte slice
//
// The values in WithWrapperOptions can also be set via the package's native
// With* functions.
func (s *Wrapper) NewDerivedWrapper(opt ...interface{}) (*Wrapper, error) {
	if len(s.keyBytes) == 0 {
		return nil, errors.New("cannot create a sub-wrapper when key bytes are not set")
	}

	opts := getOpts(opt...)

	var h func() hash.Hash
	switch opts.WithHashType {
	case wrapping.HashTypeSha256:
		h = sha256.New
	default:
		return nil, fmt.Errorf("not a supported hash type: %d", opts.WithHashType)
	}

	ret := &Wrapper{
		keyId: opts.WithKeyId,
	}
	reader := hkdf.New(h, s.keyBytes, opts.WithSalt, opts.WithInfo)

	switch opts.WithAeadType {
	case wrapping.AeadTypeAesGcm:
		ret.keyBytes = make([]byte, len(s.keyBytes))
		n, err := reader.Read(ret.keyBytes)
		if err != nil {
			return nil, fmt.Errorf("error reading bytes from derived reader: %w", err)
		}
		if n != len(s.keyBytes) {
			return nil, fmt.Errorf("expected to read %d bytes, but read %d bytes from derived reader", len(s.keyBytes), n)
		}
		if err := ret.SetAesGcmKeyBytes(ret.keyBytes); err != nil {
			return nil, fmt.Errorf("error setting derived AES GCM key: %w", err)
		}

	default:
		return nil, fmt.Errorf("not a supported aead type: %d", opts.WithAeadType)
	}

	return ret, nil
}

// SetConfig sets the fields on the Wrapper object
//
// Supported options:
//
// * wrapping.WithKeyId: The key ID, if any, to set on the wrapper
//
// * wrapping.WithWrapperOptions: A struct containing the following:
//
// ** "aead_type": The type of AEAD to use, defaults to wrapping.AeadTypeAesGcm
//
// ** "key": A base-64 encoded string value containing the key to use
//
// The values in WithWrapperOptions can also be set via the package's native
// With* functions.
func (s *Wrapper) SetConfig(_ context.Context, opt ...interface{}) (*wrapping.WrapperConfig, error) {
	opts := getOpts(opt...)

	s.keyId = opts.WithKeyId

	if opts.WithKey == "" {
		return nil, nil
	}

	switch opts.WithAeadType {
	case wrapping.AeadTypeAesGcm:
		keyRaw, err := base64.StdEncoding.DecodeString(opts.WithKey)
		if err != nil {
			return nil, fmt.Errorf("error base64-decoding key: %w", err)
		}
		if err := s.SetAesGcmKeyBytes(keyRaw); err != nil {
			return nil, fmt.Errorf("error setting AES GCM key: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported aead_type %q", opts.WithAeadType.String())
	}

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["aead_type"] = opts.WithAeadType.String()

	return wrapConfig, nil
}

// GetKeyBytes returns the current key bytes
func (s *Wrapper) GetKeyBytes() []byte {
	return s.keyBytes
}

// SetAead allows directly setting an AEAD to use
func (s *Wrapper) SetAead(aead cipher.AEAD) {
	s.aead = aead
}

// SetAesGcmKeyBytes takes in a byte slice and constucts an AES-GCM AEAD from it
func (s *Wrapper) SetAesGcmKeyBytes(key []byte) error {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return err
	}

	s.keyBytes = key
	s.aead = aead
	return nil
}

// Type returns the seal type for this particular Wrapper implementation
func (s *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeAead, nil
}

func (s *ShamirWrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeShamir, nil
}

// KeyId returns the last known key id
func (s *Wrapper) KeyId(_ context.Context) (string, error) {
	return s.keyId, nil
}

// Encrypt is used to encrypt the plaintext using the AEAD held by the wrapper
//
// Supported options:
//
// * wrapping.WithAad: Additional authenticated data that should be sourced from
// a separate location, and must also be provided during decryption
func (s *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...interface{}) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	if s.aead == nil {
		return nil, errors.New("aead is not configured in the seal")
	}

	iv, err := uuid.GenerateRandomBytes(12)
	if err != nil {
		return nil, err
	}

	opts := getOpts(opt...)

	ciphertext := s.aead.Seal(nil, iv, plaintext, opts.WithAad)

	return &wrapping.BlobInfo{
		Ciphertext: append(iv, ciphertext...),
		KeyInfo: &wrapping.KeyInfo{
			KeyId: s.keyId,
		},
	}, nil
}

// Decrypt is used to decrypt the ciphertext using the AEAD held by the wrapper
//
// Supported options:
//
// * wrapping.WithAad: Additional authenticated data that should be sourced from
// a separate location, and must match what was provided during encryption
func (s *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...interface{}) ([]byte, error) {
	if in == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	if s.aead == nil {
		return nil, errors.New("aead is not configured in the seal")
	}

	iv, ciphertext := in.Ciphertext[:12], in.Ciphertext[12:]

	opts := getOpts(opt...)

	plaintext, err := s.aead.Open(nil, iv, ciphertext, opts.WithAad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

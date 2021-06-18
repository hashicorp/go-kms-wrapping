package aead

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

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
func NewWrapper(opt ...wrapping.Option) *Wrapper {
	seal := new(Wrapper)
	return seal
}

// Deprecated: NewShamirWrapper returns a type of "shamir" instead of "aead" and
// is for backwards compatibility with old versions of Vault. Do not use in new
// code.
func NewShamirWrapper(opt ...wrapping.Option) *ShamirWrapper {
	return &ShamirWrapper{
		Wrapper: NewWrapper(opt...),
	}
}

// NewDerivedWrapper returns an aead.Wrapper whose key is set to an hkdf-based
// derivation from the original wrapper
//
// Supported options:
//
// * WithAeadType: The AEAD type to use when encrypting
//
// * WithHash: The hash function to use for derivation (defaults to sha256)
//
// * WithInfo: The info value, if any, to use in the derivation
//
// * WithKeyId: The key ID, if any, to set on the derived wrapper
//
// * WithSalt: The salt value, if any, to use in the derivation
func (s *Wrapper) NewDerivedWrapper(opt ...wrapping.Option) (*Wrapper, error) {
	if len(s.keyBytes) == 0 {
		return nil, errors.New("cannot create a sub-wrapper when key byte are not set")
	}

	opts := wrapping.GetOpts(opt...)

	h := opts.WithHash
	if h == nil {
		h = sha256.New
	}

	ret := &Wrapper{
		keyId: opts.WithKeyId,
	}
	reader := hkdf.New(h, s.keyBytes, opts.WithSalt, opts.WithInfo)

	switch opts.WithAeadType {
	case wrapping.AeadTypeDefault, wrapping.AeadTypeAesGcm:
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
		return nil, fmt.Errorf("not a supported aead type: %q", opts.WithAeadType.String())
	}

	return ret, nil
}

// SetConfig sets the fields on the Wrapper object
//
// Supported options:
//
// * WithKeyId: The key ID, if any, to set on the wrapper
//
// * WithAeadType: The AEAD type to use when encrypting
//
// * WithKey: The key bytes (base64-encoded) the wrapper should use
func (s *Wrapper) SetConfig(opt ...wrapping.Option) (map[string]string, error) {
	opts := wrapping.GetOpts(opt...)

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
	wrappingInfo := make(map[string]string)
	wrappingInfo["aead_type"] = opts.WithAeadType.String()

	return wrappingInfo, nil
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
func (s *Wrapper) Type() wrapping.WrapperType {
	return wrapping.WrapperTypeAead
}

func (s *ShamirWrapper) Type() wrapping.WrapperType {
	return wrapping.WrapperTypeShamir
}

// KeyId returns the last known key id
func (s *Wrapper) KeyId() string {
	return s.keyId
}

// Encrypt is used to encrypt the plaintext using the aead held by the seal.
func (s *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
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

	opts := wrapping.GetOpts(opt...)

	ciphertext := s.aead.Seal(nil, iv, plaintext, opts.WithAad)

	return &wrapping.BlobInfo{
		Ciphertext: append(iv, ciphertext...),
		KeyInfo: &wrapping.KeyInfo{
			KeyId: s.keyId,
		},
	}, nil
}

func (s *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	if s.aead == nil {
		return nil, errors.New("aead is not configured in the seal")
	}

	iv, ciphertext := in.Ciphertext[:12], in.Ciphertext[12:]

	opts := wrapping.GetOpts(opt...)

	plaintext, err := s.aead.Open(nil, iv, ciphertext, opts.WithAad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

package shamir

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
)

// ShamirWrapper implements the seal.Access interface for Shamir unseal
type ShamirWrapper struct {
	logger hclog.Logger
	key    []byte
	aead   cipher.AEAD
}

// Ensure that we are implementing AutoSealAccess
var _ wrapping.Wrapper = (*ShamirWrapper)(nil)

// NewWrapper creates a new ShamirWrapper with the provided logger
func NewWrapper(opts *wrapping.WrapperOptions) *ShamirWrapper {
	if opts == nil {
		opts = new(wrapping.WrapperOptions)
	}
	seal := &ShamirWrapper{
		logger: opts.Logger,
	}
	return seal
}

func (s *ShamirWrapper) GetKey() []byte {
	return s.key
}

func (s *ShamirWrapper) SetKey(key []byte) error {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return err
	}

	s.key = key
	s.aead = aead
	return nil
}

// Init is a no-op at the moment
func (s *ShamirWrapper) Init(_ context.Context) error {
	return nil
}

// Finalize is called during shutdown. This is a no-op since
// ShamirWrapper doesn't require any cleanup.
func (s *ShamirWrapper) Finalize(_ context.Context) error {
	return nil
}

// Type returns the seal type for this particular Wrapper implementation
func (s *ShamirWrapper) Type() string {
	return wrapping.Shamir
}

// KeyID returns the last known key id
func (s *ShamirWrapper) KeyID() string {
	return ""
}

// HMACKeyID returns the last known HMAC key id
func (s *ShamirWrapper) HMACKeyID() string {
	return ""
}

// Encrypt is used to encrypt the plaintext using the aead held by the seal.
func (s *ShamirWrapper) Encrypt(_ context.Context, plaintext []byte) (*wrapping.EncryptedBlobInfo, error) {
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

	ciphertext := s.aead.Seal(nil, iv, plaintext, nil)

	return &wrapping.EncryptedBlobInfo{
		Ciphertext: append(iv, ciphertext...),
	}, nil
}

func (s *ShamirWrapper) Decrypt(_ context.Context, in *wrapping.EncryptedBlobInfo) ([]byte, error) {
	if in == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	if s.aead == nil {
		return nil, errors.New("aead is not configured in the seal")
	}

	iv, ciphertext := in.Ciphertext[:12], in.Ciphertext[12:]

	plaintext, err := s.aead.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package static

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const (
	EnvBaoCurrentKeyValueName       = "BAO_STATIC_SEAL_CURRENT_KEY"
	EnvBaoCurrentKeyIdentifierName  = "BAO_STATIC_SEAL_CURRENT_KEY_ID"
	EnvBaoPreviousKeyValueName      = "BAO_STATIC_SEAL_PREVIOUS_KEY"
	EnvBaoPreviousKeyIdentifierName = "BAO_STATIC_SEAL_PREVIOUS_KEY_ID"
)

// Wrapper is a wrapper that leverages Vault's Transit secret
// engine
type Wrapper struct {
	logger        hclog.Logger
	previousKeyId string
	previousKey   []byte

	currentKeyId string
	currentKey   []byte
}

var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new transit wrapper
func NewWrapper() *Wrapper {
	s := &Wrapper{}
	return s
}

// SetConfig processes the config info from the server config
func (s *Wrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	s.logger = opts.withLogger

	// Load keys, identifiers from environments or options.
	currentKey := opts.withCurrentKey
	previousKey := opts.withPreviousKey

	s.currentKeyId = opts.withCurrentKeyId
	s.previousKeyId = opts.withPreviousKeyId

	if !opts.Options.WithDisallowEnvVars {
		if env := os.Getenv(EnvBaoCurrentKeyValueName); env != "" {
			currentKey = env
		}
		if env := os.Getenv(EnvBaoPreviousKeyValueName); env != "" {
			previousKey = env
		}
		if env := os.Getenv(EnvBaoCurrentKeyIdentifierName); env != "" {
			s.currentKeyId = env
		}
		if env := os.Getenv(EnvBaoPreviousKeyIdentifierName); env != "" {
			s.previousKeyId = env
		}
	}

	// Current key information
	switch len(currentKey) {
	case 64:
		// hex
		s.currentKey, err = hex.DecodeString(currentKey)
		if err != nil {
			return nil, fmt.Errorf("failed to hex decode current key: %w", err)
		}
	case 44:
		// regular base64
		s.currentKey, err = base64.StdEncoding.DecodeString(currentKey)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode current key: %w", err)
		}
	case 43:
		// raw url-safe base64
		s.currentKey, err = base64.RawURLEncoding.DecodeString(currentKey)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode current key: %w", err)
		}
	case 32:
		// raw
		s.currentKey = []byte(currentKey)
	case 0:
		return nil, errors.New("missing required current key")
	default:
		return nil, errors.New("unknown encoding for AES-256 key: must be either a raw, hex, or base64-encoded")
	}

	if len(s.currentKeyId) == 0 {
		return nil, errors.New("got empty current_key_id; please specify a permanent identifier for this key")
	}

	// Previous key information
	switch len(previousKey) {
	case 64:
		// hex
		s.previousKey, err = hex.DecodeString(previousKey)
		if err != nil {
			return nil, fmt.Errorf("failed to hex decode previous key: %w", err)
		}
	case 44:
		// regular base64
		s.previousKey, err = base64.StdEncoding.DecodeString(previousKey)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode previous key: %w", err)
		}
	case 43:
		// raw url-safe base64
		s.previousKey, err = base64.RawURLEncoding.DecodeString(previousKey)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode previous key: %w", err)
		}
	case 32:
		// raw
		s.previousKey = []byte(previousKey)
	case 0:
		// missing previous key is OK
	default:
		return nil, errors.New("unknown encoding for AES-256 key: must be either a raw, hex, or base64-encoded")
	}

	if len(s.previousKeyId) == 0 && len(s.previousKey) != 0 {
		return nil, errors.New("got empty previous_key_id with non-empty previous_key; please specify the matching key identifier")
	}
	if len(s.previousKeyId) != 0 && len(s.previousKey) == 0 {
		return nil, errors.New("got non-empty previous_key_id with empty previous_key; please specify the previous key or remove previous_key_id")
	}

	if subtle.ConstantTimeCompare(s.currentKey, s.previousKey) == 1 && s.previousKeyId != s.currentKeyId {
		return nil, errors.New("current and previous key material match with different key identifiers")
	}

	if subtle.ConstantTimeCompare(s.currentKey, s.previousKey) != 1 && s.previousKeyId == s.currentKeyId {
		return nil, errors.New("current and previous key material differs with same key identifiers")
	}

	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	if len(s.previousKeyId) > 0 {
		wrapConfig.Metadata["previous_key_id"] = s.previousKeyId
	}
	wrapConfig.Metadata["current_key_id"] = s.currentKeyId

	return wrapConfig, nil
}

// Init is called during core.Initialize
func (s *Wrapper) Init(_ context.Context) error {
	return nil
}

// Finalize is called during shutdown
func (s *Wrapper) Finalize(_ context.Context) error {
	return nil
}

// Type returns the type for this particular Wrapper implementation
func (s *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeStatic, nil
}

// KeyId returns the last known key id
func (s *Wrapper) KeyId(_ context.Context) (string, error) {
	return s.currentKeyId, nil
}

// Encrypt is used to encrypt using our static keys
func (s *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opts ...wrapping.Option) (*wrapping.BlobInfo, error) {
	opt, err := wrapping.GetOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed parsing options: %w", err)
	}

	block, err := aes.NewCipher(s.currentKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	var nonce []byte
	if len(opt.WithIv) != 12 {
		nonce = make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
	} else {
		nonce = opt.WithIv
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, opt.WithAad)

	ret := &wrapping.BlobInfo{
		Ciphertext: ciphertext,
		Iv:         nonce,
		KeyInfo: &wrapping.KeyInfo{
			KeyId: s.currentKeyId,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext
func (s *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opts ...wrapping.Option) ([]byte, error) {
	switch in.KeyInfo.KeyId {
	case s.previousKeyId:
		if s.previousKeyId == "" {
			return nil, fmt.Errorf("unknown key id for data: `%v`", in.KeyInfo.KeyId)
		}

		return s.decryptWithKey(ctx, in, s.previousKey, opts...)
	case s.currentKeyId:
		return s.decryptWithKey(ctx, in, s.currentKey, opts...)
	default:
		return nil, fmt.Errorf("unknown key id for data: `%v`", in.KeyInfo.KeyId)
	}
}

func (s *Wrapper) decryptWithKey(ctx context.Context, in *wrapping.BlobInfo, key []byte, opts ...wrapping.Option) ([]byte, error) {
	opt, err := wrapping.GetOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed parsing options: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, in.Iv, in.Ciphertext, opt.WithAad)
	if err != nil {
		return nil, fmt.Errorf("failed to open ciphertext: %w", err)
	}

	return plaintext, nil
}

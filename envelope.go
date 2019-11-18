package wrapping

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/hashicorp/errwrap"
	uuid "github.com/hashicorp/go-uuid"
)

// Envelope performs encryption or decryption, wrapping sensitive data. It creates a random key. This is usable on its own but since many KMS systems or key types cannot support large values, this is used by implementations in this package to encrypt large values with a DEK and use the actual KMS to encrypt the DEK.
type Envelope struct{}

// EnvelopeOptions is a placeholder for future options, such as the ability to switch which algorithm is used
type EnvelopeOptions struct{}

// EnvelopeInfo contains the information necessary to perfom encryption or decryption in an envelope fashion
type EnvelopeInfo struct {
	Ciphertext []byte
	Key        []byte
	IV         []byte
}

// NewEnvelope retuns an Envelope that is ready to use for use. It is valid to pass nil EnvelopeOptions.
func NewEnvelope(opts *EnvelopeOptions) *Envelope {
	return &Envelope{}
}

// Encrypt takes in plaintext and envelope encrypts it, generating an EnvelopeInfo value
func (e *Envelope) Encrypt(plaintext []byte, additionalData []byte) (*EnvelopeInfo, error) {
	// Generate DEK
	key, err := uuid.GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	iv, err := uuid.GenerateRandomBytes(12)
	if err != nil {
		return nil, err
	}
	aead, err := e.aeadEncrypter(key)
	if err != nil {
		return nil, err
	}

	return &EnvelopeInfo{
		Ciphertext: aead.Seal(nil, iv, plaintext, additionalData),
		Key:        key,
		IV:         iv,
	}, nil
}

// Decrypt takes in EnvelopeInfo and potentially additional data and decrypts. Additional data is separate from the encrypted blob info as it is expected that will be sourced from a separate location.
func (e *Envelope) Decrypt(data *EnvelopeInfo, additionalData []byte) ([]byte, error) {
	aead, err := e.aeadEncrypter(data.Key)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, data.IV, data.Ciphertext, additionalData)
}

func (e *Envelope) aeadEncrypter(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errwrap.Wrapf("failed to create cipher: {{err}}", err)
	}

	// Create the GCM mode AEAD
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.New("failed to initialize GCM mode")
	}

	return gcm, nil
}

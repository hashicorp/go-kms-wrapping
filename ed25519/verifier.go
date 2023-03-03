package ed25519

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// Verifier provides and ed25519 implementation for the wrapping.Verifier interface
type Verifier struct {
	pubKey      ed25519.PublicKey
	keyId       string
	keyPurposes []wrapping.KeyPurpose
	keyType     wrapping.KeyType
}

var _ wrapping.SigInfoVerifier = (*Verifier)(nil)
var _ wrapping.KeyExporter = (*Verifier)(nil)

// NewVerifier creates a new verifier.  Supported options: WithKeyId,
// WithKeyPurposes, WithPubKey
func NewVerifier(ctx context.Context, opt ...wrapping.Option) (*Verifier, error) {
	const op = "crypto.NewEd25519Verifier"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if len(opts.WithKeyPurposes) == 0 {
		opts.WithKeyPurposes = append(opts.WithKeyPurposes, wrapping.KeyPurpose_Verify)
	}
	return &Verifier{
		pubKey:      opts.WithPubKey,
		keyId:       opts.WithKeyId,
		keyPurposes: opts.WithKeyPurposes,
		keyType:     wrapping.KeyType_ED25519,
	}, nil
}

// SetConfig sets the fields on the Signer
//
// Supported options: wrapping.WithKeyId, wrapping.WithKeyPurposes,
// wrapping.WithConfigMap and the local WithPubKey
//
// wrapping.WithConfigMap supports a ConfigPubKey to set the Signer pub key.
// along with ConfigKeyId, and ConfigKeyPurposes.  ConfigKeyPurposes are a
// comma delimited list of wrapping.KeyPurpose_name values (for example:
// "Sign, Verify")
//
// The values in WithConfigMap can also be set via the package's native local
// options.
func (s *Verifier) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	const op = "ed25519.(Signer).SetConfig"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	switch {
	case len(opts.WithPubKey) == 0:
		return nil, fmt.Errorf("%s: missing public key: %w", op, wrapping.ErrInvalidParameter)
	}

	s.keyId = opts.WithKeyId
	s.keyPurposes = opts.WithKeyPurposes
	s.pubKey = opts.WithPubKey

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)

	marshaledKey, err := x509.MarshalPKIXPublicKey(s.pubKey)
	if err != nil {
		return nil, fmt.Errorf("%s: error marshaling public key: %w", op, err)
	}
	wrapConfig.Metadata[ConfigPubKey] = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: marshaledKey}))

	return wrapConfig, nil
}

// Verify will verify the signature of the provided msg.  No options are currently supported.
func (s *Verifier) Verify(ctx context.Context, msg []byte, sig *wrapping.SigInfo) (bool, error) {
	const op = "crypto.(Ed25519Verifier).Verify"
	switch {
	case s.pubKey == nil:
		return false, fmt.Errorf("%s: missing public key: %w", op, wrapping.ErrInvalidParameter)
	case msg == nil:
		return false, fmt.Errorf("%s: missing message: %w", op, wrapping.ErrInvalidParameter)
	case sig == nil:
		return false, fmt.Errorf("%s: missing sig info: %w", op, wrapping.ErrInvalidParameter)
	}
	return ed25519.Verify(s.pubKey, msg, sig.Signature), nil
}

// KeyBytes returns the current key bytes
func (s *Verifier) KeyBytes(context.Context) ([]byte, error) {
	if s.pubKey == nil {
		return nil, fmt.Errorf("missing bytes: %w", wrapping.ErrInvalidParameter)
	}
	return s.pubKey, nil
}

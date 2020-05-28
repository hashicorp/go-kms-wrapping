package x25519

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"golang.org/x/crypto/curve25519"
)

// Wrapper uses the RFC7748 X25519 ECDH mechanism for encryption. Specifically,
// it can perform the X25519 function and return it, and it can use the result
// of such a function in an encryption operation along with local scalar/point
// information. In this way you can configure it with a scalar/point and
// someone else's X25519 output to have it generate a shared key. This is then
// used in a key derivation function (unless disabled) along with both X25519
// outputs to generate an actual encryption key, using our multiplication
// result as salt and the remote as info.
type Wrapper struct {
	keyID             string
	scalar            []byte
	point             []byte
	ourMultResult     []byte
	remoteMultResult  []byte
	disableDerivation bool
}

var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper returns a new wrapper
func NewWrapper(_ *wrapping.WrapperOptions) *Wrapper {
	w := &Wrapper{
		point: curve25519.Basepoint,
	}
	return w
}

// SetConfig sets the fields on the Wrapper object based on values from the
// config parameter.
func (w *Wrapper) SetConfig(config map[string]string) (map[string]string, error) {
	if config == nil {
		config = map[string]string{}
	}

	w.keyID = config["key_id"]

	disableDerivationStr := config["disable_derivation"]
	if disableDerivationStr != "" {
		var err error
		w.disableDerivation, err = strconv.ParseBool(disableDerivationStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing disable_verification value: %w", err)
		}
	}

	scalarStr := config["scalar"]
	if scalarStr != "" {
		scalar, err := base64.StdEncoding.DecodeString(scalarStr)
		if err != nil {
			return nil, fmt.Errorf("error base64-decoding scalar: %w", err)
		}
		if err := w.SetScalar(scalar); err != nil {
			return nil, fmt.Errorf("error setting scalar: %w", err)
		}
	}

	pointStr := config["point"]
	if pointStr != "" {
		point, err := base64.StdEncoding.DecodeString(pointStr)
		if err != nil {
			return nil, fmt.Errorf("error base64-decoding point: %w", err)
		}
		if err := w.SetPoint(point); err != nil {
			return nil, fmt.Errorf("error setting point: %w", err)
		}
	}

	remoteMultResultStr := config["remote_x25519_output"]
	if remoteMultResultStr != "" {
		remoteMultResult, err := base64.StdEncoding.DecodeString(remoteMultResultStr)
		if err != nil {
			return nil, fmt.Errorf("error base64-decoding remote_x25519_output: %w", err)
		}
		if err := w.SetRemoteX25519Output(remoteMultResult); err != nil {
			return nil, fmt.Errorf("error setting point: %w", err)
		}
	}

	return map[string]string{}, nil
}

// Scalar sets the scalar. This value is private/secret. Deriving from purely
// random bytes is usually the best option.
func (w *Wrapper) SetScalar(scalar []byte) error {
	if len(scalar) != 32 {
		return errors.New("scalar must be 32 bytes")
	}
	w.scalar = scalar

	return w.calculateOurResult()
}

// SetPoint sets the point. If nil, the default base point is used. Otherwise
// it should be the output of the X25519 function from the curve25519 library.
// This value is public.
func (w *Wrapper) SetPoint(point []byte) error {
	if point == nil {
		w.point = curve25519.Basepoint
		return nil
	}
	if len(point) != 32 {
		return errors.New("point must be 32 bytes, or nil to use base point")
	}
	w.point = point

	if w.scalar != nil {
		return w.calculateOurResult()
	}
	return nil
}

func (w *Wrapper) SetRemoteX25519Output(remoteOutput []byte) error {
	if len(remoteOutput) != 32 {
		return errors.New("remote output must be 32 bytes")
	}
	w.remoteMultResult = remoteOutput
	return nil
}

func (w *Wrapper) X25519Output() ([]byte, error) {
	if len(w.ourMultResult) != 32 {
		if err := w.calculateOurResult(); err != nil {
			return nil, err
		}
	}
	if len(w.ourMultResult) != 32 {
		return nil, errors.New("our X25519 output is invalid")
	}

	return w.ourMultResult, nil
}

func (w *Wrapper) calculateOurResult() error {
	ourResult, err := curve25519.X25519(w.scalar, w.point)
	if err != nil {
		return fmt.Errorf("error calculating X25519 function: %w", err)
	}

	w.ourMultResult = ourResult
	return nil
}

// Init is a no-op at the moment
func (w *Wrapper) Init(_ context.Context) error {
	return nil
}

// Finalize is called during shutdown. This is a no-op since Wrapper doesn't
// require any cleanup.
func (w *Wrapper) Finalize(_ context.Context) error {
	return nil
}

// Type returns the type of this implementation
func (w *Wrapper) Type() string {
	return wrapping.X25519
}

// KeyID returns the set key ID
func (w *Wrapper) KeyID() string {
	return w.keyID
}

// HMACKeyID returns the last known HMAC key id
func (w *Wrapper) HMACKeyID() string {
	return ""
}

func (w *Wrapper) Encrypt(_ context.Context, plaintext, aad []byte) (*wrapping.EncryptedBlobInfo, error) {
	wrapper, err := w.getSharedKeyWrapper()
	if err != nil {
		return nil, err
	}

	return wrapper.Encrypt(nil, plaintext, aad)
}

func (w *Wrapper) Decrypt(_ context.Context, blobInfo *wrapping.EncryptedBlobInfo, aad []byte) ([]byte, error) {
	wrapper, err := w.getSharedKeyWrapper()
	if err != nil {
		return nil, err
	}

	return wrapper.Decrypt(nil, blobInfo, aad)
}

func (w *Wrapper) deriveSharedKey() ([]byte, error) {
	if len(w.remoteMultResult) != 32 {
		return nil, errors.New("remote x25519 output is invalid")
	}
	if len(w.scalar) != 32 {
		return nil, errors.New("our scalar is invalid")
	}

	return curve25519.X25519(w.scalar, w.remoteMultResult)
}

func (w *Wrapper) getSharedKeyWrapper() (wrapping.Wrapper, error) {
	sharedKey, err := w.deriveSharedKey()
	if err != nil {
		return nil, fmt.Errorf("error deriving shared key: %w", err)
	}

	var wrapper *aead.Wrapper
	switch w.disableDerivation {
	case true:
		wrapper = aead.NewWrapper(nil)
		wrapper.SetRawKey(sharedKey)
	default:
		if len(w.ourMultResult) != 32 {
			return nil, fmt.Errorf("our x25519 output is invalid")
		}
		wrapper, err = aead.NewWrapper(nil).NewDerivedWrapper(&aead.DerivedWrapperOptions{
			KeyBytes: sharedKey,
			Salt:     w.ourMultResult,
			Info:     w.remoteMultResult,
		})
		if err != nil {
			return nil, fmt.Errorf("error creating derived wrapper: %w", err)
		}
	}

	return wrapper, nil
}

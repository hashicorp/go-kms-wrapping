package multiwrapper

import (
	"context"
	"errors"
	sync "sync"

	wrapping "github.com/hashicorp/go-kms-wrapping"
)

const baseEncryptor = "__base__"

var _ wrapping.Wrapper = (*MultiWrapper)(nil)

var ErrKeyNotFound = errors.New("given key ID not found")

// MultiWrapper allows multiple wrappers to be used for decryption based on key
// ID. This allows for rotation of data by allowing data to be decrypted across
// multiple (possibly derived) wrappers and encrypted with the default.
// Functions on this type will likely panic if the wrapper is not created via
// NewMultiWrapper.
type MultiWrapper struct {
	wrappers *sync.Map
}

// NewMultiWrapper creates a MultiWrapper and sets its encrypting wrapper to
// the one that is passed in. This function will panic if base is nil.
func NewMultiWrapper(base wrapping.Wrapper) *MultiWrapper {
	// For safety, no real reason this should happen
	if base.KeyID() == baseEncryptor {
		panic("invalid key ID")
	}

	ret := &MultiWrapper{
		wrappers: new(sync.Map),
	}
	ret.wrappers.Store(baseEncryptor, base)
	return ret
}

// AddWrapper adds a wrapper to the MultiWrapper. For safety, it will refuse to
// overwrite an existing wrapper; use RemoveWrapper to remove that one first.
// The return parameter indicates if the wrapper was successfully added, that
// is, it will be false if an existing wrapper would have been overridden. If
// you want to change the encrypting wrapper, create a new MultiWrapper. This
// function will panic if w is nil.
func (m *MultiWrapper) AddWrapper(w wrapping.Wrapper) (added bool) {
	_, loaded := m.wrappers.LoadOrStore(w.KeyID(), w)
	return !loaded
}

// RemoveWrapper removes a wrapper from the MultiWrapper, identified by key ID.
// It will not remove the encrypting wrapper; use SetEncryptingWrapper for
// that.
func (m *MultiWrapper) RemoveWrapper(keyID string) {
	// Don't allow removing our base encryptor
	if keyID == baseEncryptor {
		return
	}
	m.wrappers.Delete(keyID)
}

// SetEncryptingWrapper resets the encrypting wrapper to the one passed in. It
// will also add the previous encrypting wrapper to the set of decrypting
// wrappers; it can then be removed via its key ID and RemoveWrapper if
// desired. It will panic if w is nil. It will return false (not successful) if
// the given key ID is already in use.
func (m *MultiWrapper) SetEncryptingWrapper(w wrapping.Wrapper) (success bool) {
	// For safety, no real reason this should happen
	if w.KeyID() == baseEncryptor {
		panic("invalid key ID")
	}

	// Note: we keep this simple and don't return errors because there are no
	// reasonable ways this should fail, other than trying to give a new
	// encryptor with an existing key ID.
	val, ok := m.wrappers.Load(baseEncryptor)
	if !ok {
		m.wrappers.Store(baseEncryptor, w)
		return true
	}
	oldW := val.(wrapping.Wrapper)
	_, loaded := m.wrappers.LoadOrStore(oldW.KeyID(), oldW)
	if loaded {
		return false
	}

	m.wrappers.Store(baseEncryptor, w)
	return true
}

func (m *MultiWrapper) encryptor() wrapping.Wrapper {
	val, ok := m.wrappers.Load(baseEncryptor)
	if !ok {
		panic("no base encryptor found")
	}
	return val.(wrapping.Wrapper)
}

func (m *MultiWrapper) Type() string {
	return wrapping.MultiWrapper
}

// KeyID returns the KeyID of the current encryptor
func (m *MultiWrapper) KeyID() string {
	return m.encryptor().KeyID()
}

// HMACKeyID returns the HMACKeyID of the current encryptor
func (m *MultiWrapper) HMACKeyID() string {
	return m.encryptor().HMACKeyID()
}

// This does nothing; it's up to the user to initialize and finalize any given
// wrapper
func (m *MultiWrapper) Init(context.Context) error {
	return nil
}

// This does nothing; it's up to the user to initialize and finalize any given
// wrapper
func (m *MultiWrapper) Finalize(context.Context) error {
	return nil
}

// Encrypt encrypts using the current encryptor
func (m *MultiWrapper) Encrypt(ctx context.Context, pt []byte, aad []byte) (*wrapping.EncryptedBlobInfo, error) {
	return m.encryptor().Encrypt(ctx, pt, aad)
}

// Decrypt will use the embedded KeyID in the encrypted blob info to select
// which wrapper to use for decryption. If there is no key info it will attempt
// decryption with the current encryptor. It will return an ErrKeyNotFound if
// it cannot find a suitable key.
func (m *MultiWrapper) Decrypt(ctx context.Context, ct *wrapping.EncryptedBlobInfo, aad []byte) ([]byte, error) {
	// First check the encryptor
	enc := m.encryptor()
	if ct.KeyInfo == nil || ct.KeyInfo.KeyID == enc.KeyID() {
		return enc.Decrypt(ctx, ct, aad)
	}

	val, ok := m.wrappers.Load(ct.KeyInfo.KeyID)
	if !ok {
		return nil, ErrKeyNotFound
	}
	return val.(wrapping.Wrapper).Decrypt(ctx, ct, aad)
}

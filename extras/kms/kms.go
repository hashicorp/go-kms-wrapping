package kms

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/multi"
	"github.com/hashicorp/go-multierror"
)

// cachePurpose defines an enum for wrapper cache purposes
type cachePurpose int

const (
	// unknownWrapperCache is the default, and indicates that a purpose wasn't
	// specified
	unknownWrapperCache cachePurpose = iota

	// externalWrapperCache defines an external wrapper cache
	externalWrapperCache

	// scopeWrapperCache defines an scope wrapper cache
	scopeWrapperCache
)

// Kms is a way to access wrappers for a given scope and purpose. Since keys can
// never change, only be added or (eventually) removed, it opportunistically
// caches, going to the database as needed.
type Kms struct {
	// scopedWrapperCache holds a per-scope-purpose multiwrapper containing the
	// current encrypting key and all previous key versions, for decryption
	scopedWrapperCache sync.Map

	externalWrapperCache sync.Map

	purposes []KeyPurpose
	repo     *repository
}

// New takes in a reader, writer and a list of key purposes it will support.
// Every kms will support a KeyPurposeRootKey by default and it doesn't need to
// be passed in as one of the supported purposes.  No options are currently
// supported.
func New(r dbw.Reader, w dbw.Writer, purposes []KeyPurpose, _ ...Option) (*Kms, error) {
	const op = "kms.New"
	repo, err := newRepository(r, w)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to initialize repository: %w", op, err)
	}
	purposes = append(purposes, KeyPurposeRootKey)
	removeDuplicatePurposes(purposes)

	return &Kms{
		purposes: purposes,
		repo:     repo,
	}, nil
}

func (k *Kms) addKey(ctx context.Context, cPurpose cachePurpose, kPurpose KeyPurpose, wrapper wrapping.Wrapper, opt ...Option) error {
	const (
		op        = "kms.addKey"
		missingId = ""
	)
	if kPurpose == KeyPurposeUnknown {
		return fmt.Errorf("%s: missing purpose: %w", op, ErrInvalidParameter)
	}
	if isNil(wrapper) {
		return fmt.Errorf("%s: missing wrapper: %w", op, ErrInvalidParameter)
	}
	if !purposeListContains(k.purposes, kPurpose) {
		return fmt.Errorf("%s: not a supported key purpose %q: %w", op, kPurpose, ErrInvalidParameter)
	}
	opts := getOpts(opt...)

	keyId, err := wrapper.KeyId(ctx)
	if err != nil {
		return fmt.Errorf("%s: error reading wrapper key ID: %w", op, err)
	}
	if keyId == missingId {
		return fmt.Errorf("%s: wrapper has no key ID: %w", op, ErrInvalidParameter)
	}
	switch cPurpose {
	case externalWrapperCache:
		k.externalWrapperCache.Store(kPurpose, wrapper)
	case scopeWrapperCache:
		if opts.withKeyId == "" {
			return fmt.Errorf("%s: missing key id for scoped wrapper cache: %w", op, ErrInvalidParameter)
		}
		k.scopedWrapperCache.Store(opts.withKeyId, wrapper)
	default:
		return fmt.Errorf("%s: unsupported cache purpose %q: %w", op, cPurpose, ErrInvalidParameter)
	}
	return nil
}

// Purposes returns a copy of the key purposes for the kms
func (k *Kms) Purposes() []KeyPurpose {
	cp := make([]KeyPurpose, len(k.purposes))
	copy(cp, k.purposes)
	return cp
}

// AddExternalWrapper allows setting the external keys which are defined outside
// of the kms (e.g. in a configuration file).
func (k *Kms) AddExternalWrapper(ctx context.Context, purpose KeyPurpose, wrapper wrapping.Wrapper) error {
	// TODO: If we support more than one, e.g. for encrypting against many in case
	// of a key loss, there will need to be some refactoring here to have the values
	// being stored in the struct be a multiwrapper, but that's for a later project.
	return k.addKey(ctx, externalWrapperCache, purpose, wrapper)
}

// GetExternalWrapper returns the external wrapper for a given purpose and
// returns ErrKeyNotFound when a key for the given purpose is not found.
func (k *Kms) GetExternalWrapper(_ context.Context, purpose KeyPurpose) (wrapping.Wrapper, error) {
	const op = "kms.(Kms).GetExternalWrapper"
	if purpose == KeyPurposeUnknown {
		return nil, fmt.Errorf("%s: missing purpose: %w", op, ErrInvalidParameter)
	}
	if !purposeListContains(k.purposes, purpose) {
		return nil, fmt.Errorf("%s: not a supported key purpose %q: %w", op, purpose, ErrInvalidParameter)
	}
	if k, ok := k.externalWrapperCache.Load(purpose); ok {
		w, ok := k.(wrapping.Wrapper)
		if !ok {
			return nil, fmt.Errorf("%s: external wrapper is not a wrapping.Wrapper: %w", op, ErrInternal)
		}
		return w, nil
	}
	return nil, fmt.Errorf("%s: missing external wrapper for %q: %w", op, purpose, ErrKeyNotFound)
}

// GetExternalRootWrapper returns the external wrapper for KeyPurposeRootKey is
// is just a convenience function for GetExternalWrapper(...) and returns
// ErrKeyNotFound when a root key is not found.
func (k *Kms) GetExternalRootWrapper() (wrapping.Wrapper, error) {
	const op = "kms.(Kms).GetRootWrapper"
	if k, err := k.GetExternalWrapper(context.Background(), KeyPurposeRootKey); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("%s: missing external root wrapper: %w", op, ErrKeyNotFound)
}

// GetWrapper returns a wrapper for the given scope and purpose. When a keyId is
// passed, it will ensure that the returning wrapper has that key ID in the
// multiwrapper. This is not necessary for encryption but should be supplied for
// decryption.
//
// Note: getting a wrapper for KeyPurposeRootKey is supported, but a root
// wrapper is a KEK and should never be used for data encryption.
func (k *Kms) GetWrapper(ctx context.Context, scopeId string, purpose KeyPurpose, opt ...Option) (wrapping.Wrapper, error) {
	const op = "kms.GetWrapper"
	if scopeId == "" {
		return nil, fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	if purpose == KeyPurposeUnknown {
		return nil, fmt.Errorf("%s: missing purpose: %w", op, ErrInvalidParameter)
	}
	if !purposeListContains(k.purposes, purpose) {
		return nil, fmt.Errorf("%s: not a supported key purpose %q: %w", op, purpose, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	// Fast-path: we have a valid key at the scope/purpose. Verify the key with
	// that ID is in the multiwrapper; if not, fall through to reload from the
	// DB.
	val, ok := k.scopedWrapperCache.Load(scopeId + string(purpose))
	if ok {
		wrapper, ok := val.(*multi.PooledWrapper)
		if !ok {
			return nil, fmt.Errorf("%s: scoped wrapper is not a multi.PooledWrapper: %w", op, ErrInternal)
		}
		if opts.withKeyId == "" {
			return wrapper, nil
		}
		if keyIdWrapper := wrapper.WrapperForKeyId(opts.withKeyId); keyIdWrapper != nil {
			return keyIdWrapper, nil
		}
		// Fall through to refresh our multiwrapper for this scope/purpose from the DB
	}

	// We don't have it cached, so we'll need to read from the database. Get the
	// root for the scope as we'll need it to decrypt the value coming from the
	// DB. We don't cache the roots as we expect that after a few calls the
	// scope-purpose cache will catch everything in steady-state.
	rootWrapper, rootKeyId, err := k.loadRoot(ctx, scopeId, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: error loading root key for scope %q: %w", op, scopeId, err)
	}
	if isNil(rootWrapper) {
		return nil, fmt.Errorf("%s: got nil root wrapper for scope %q: %w", op, scopeId, ErrInvalidParameter)
	}

	if purpose == KeyPurposeRootKey {
		return rootWrapper, nil
	}

	wrapper, err := k.loadDek(ctx, scopeId, purpose, rootWrapper, rootKeyId, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: error loading %q for scope %q: %w", op, purpose, scopeId, err)
	}
	k.addKey(ctx, scopeWrapperCache, purpose, wrapper, WithKeyId(scopeId+string(purpose)))

	if opts.withKeyId != "" {
		if keyIdWrapper := wrapper.WrapperForKeyId(opts.withKeyId); keyIdWrapper != nil {
			return keyIdWrapper, nil
		}
		return nil, fmt.Errorf("%s: unable to find specified key ID: %w", op, ErrKeyNotFound)
	}

	return wrapper, nil
}

// CreateKeys creates the root key and DEKs for the given scope id.  By
// default, CreateKeys manages its own transaction (begin/rollback/commit).
//
// It's valid to provide no KeyPurposes (nil or empty), which means that the
// scope will only end up with a root key (and one rk version) with no DEKs.
//
// CreateKeys also supports the WithTx(...) and WithReaderWriter(...) options
// which allows the caller to pass an inflight transaction to be used for all
// database operations.  If WithTx(...) or WithReaderWriter(...) are used, then
// the caller is responsible for managing the transaction.  The purpose of the
// WithTx(...) and WithReaderWriter(...) options are to allow the caller to
// create the scope and all of its keys in the same transaction.
//
// The WithRandomReadear(...) option is supported as well.  If no optional
// random reader is provided, then the reader from crypto/rand will be used as
// a default.
func (k *Kms) CreateKeys(ctx context.Context, scopeId string, purposes []KeyPurpose, opt ...Option) error {
	const op = "kms.(Kms).CreateKeysTx"
	if scopeId == "" {
		return fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	for _, p := range purposes {
		if !purposeListContains(k.purposes, p) {
			return fmt.Errorf("%s: not a supported key purpose %q: %w", op, p, ErrInvalidParameter)
		}
	}

	rootWrapper, err := k.GetExternalRootWrapper()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	opts := getOpts(opt...)

	if isNil(opts.withRandomReader) {
		opts.withRandomReader = rand.Reader
	}

	var localTx *dbw.RW
	var r dbw.Reader
	var w dbw.Writer
	switch {
	case opts.withTx != nil:
		if opts.withReader != nil || opts.withWriter != nil {
			return fmt.Errorf("%s: WithTx(...) and WithReaderWriter(...) options cannot be used at the same time: %w", op, ErrInvalidParameter)
		}
		if ok := opts.withTx.IsTx(); !ok {
			return fmt.Errorf("%s: provided transaction has no inflight transaction: %w", op, ErrInvalidParameter)
		}
		r = opts.withTx
		w = opts.withTx
	case opts.withReader != nil, opts.withWriter != nil:
		if opts.withTx != nil {
			return fmt.Errorf("%s: WithTx(...) and WithReaderWriter(...) options cannot be used at the same time: %w", op, ErrInvalidParameter)
		}
		if opts.withReader == nil {
			return fmt.Errorf("%s: WithReaderWriter(...) option is missing the reader: %w", op, ErrInvalidParameter)
		}
		if opts.withWriter == nil {
			return fmt.Errorf("%s: WithReaderWriter(...) option is missing the writer: %w", op, ErrInvalidParameter)
		}
		r = opts.withReader
		w = opts.withWriter
	default:
		localTx, err = k.repo.writer.Begin(ctx)
		if err != nil {
			return fmt.Errorf("%s: unable to begin transaction: %w", op, err)
		}
		r = localTx
		w = localTx
	}

	if _, err := createKeysTx(ctx, r, w, rootWrapper, opts.withRandomReader, scopeId, purposes...); err != nil {
		if localTx != nil {
			if rollBackErr := localTx.Rollback(ctx); rollBackErr != nil {
				err = multierror.Append(err, rollBackErr)
			}
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	if localTx != nil {
		if err := localTx.Commit(ctx); err != nil {
			return fmt.Errorf("%s: unable to commit transaction: %w", op, err)
		}
	}

	return nil
}

// ValidateSchema will validate the database schema against the module's
// required migrations.Version
func (k *Kms) ValidateSchema(ctx context.Context) (string, error) {
	const op = "kms.(Repository).validateVersion"
	return k.repo.ValidateSchema(ctx)
}

// ReconcileKeys will reconcile the keys in the kms against known possible
// issues.  This function reconciles the global scope unless the
// WithScopeIds(...) option is provided
//
// The WithRandomReader(...) option is supported as well.  If an optional
// random reader is not provided (is nill), then the reader from crypto/rand
// will be used as a default.
func (k *Kms) ReconcileKeys(ctx context.Context, scopeIds []string, purposes []KeyPurpose, opt ...Option) error {
	const op = "kms.ReconcileKeys"
	if len(scopeIds) == 0 {
		return fmt.Errorf("%s: missing scope ids: %w", op, ErrInvalidParameter)
	}
	for _, p := range purposes {
		if !purposeListContains(k.purposes, p) {
			return fmt.Errorf("%s: not a supported key purpose %q: %w", op, p, ErrInvalidParameter)
		}
	}

	opts := getOpts(opt...)
	if isNil(opts.withRandomReader) {
		opts.withRandomReader = rand.Reader
	}

	for _, id := range scopeIds {
		var scopeRootWrapper *multi.PooledWrapper

		for _, purpose := range purposes {
			if _, err := k.GetWrapper(ctx, id, purpose); err != nil {
				switch {
				case errors.Is(err, ErrKeyNotFound):
					if scopeRootWrapper == nil {
						if scopeRootWrapper, _, err = k.loadRoot(ctx, id); err != nil {
							return fmt.Errorf("%s: %w", op, err)
						}
					}
					key, err := generateKey(ctx, opts.withRandomReader)
					if err != nil {
						return fmt.Errorf("%s: error generating random bytes for %q key in scope %q: %w", op, purpose, id, err)
					}

					if _, _, err := k.repo.CreateDataKey(ctx, scopeRootWrapper, purpose, key); err != nil {
						return fmt.Errorf("%s: error creating %q key in scope %s: %w", op, purpose, id, err)
					}
				default:
					return fmt.Errorf("%s: %w", op, err)
				}
			}
		}
	}
	return nil
}

func (k *Kms) loadRoot(ctx context.Context, scopeId string, opt ...Option) (*multi.PooledWrapper, string, error) {
	const op = "kms.loadRoot"
	if scopeId == "" {
		return nil, "", fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	repo := opts.withRepository
	if repo == nil {
		repo = k.repo
	}
	rootKeys, err := repo.ListRootKeys(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", op, err)
	}
	var rootKeyId string
	for _, k := range rootKeys {
		if k.ScopeId == scopeId {
			rootKeyId = k.PrivateId
			break
		}
	}
	if rootKeyId == "" {
		return nil, "", fmt.Errorf("%s: missing root key for scope %q: %w", op, scopeId, ErrKeyNotFound)
	}

	// Now: find the external KMS that can be used to decrypt the root values
	// from the DB.
	externalRootWrapper, err := k.GetExternalRootWrapper()
	if err != nil {
		return nil, "", fmt.Errorf("%s: missing root key wrapper for scope %q: %w", op, scopeId, ErrKeyNotFound)
	}

	rootKeyVersions, err := repo.ListRootKeyVersions(ctx, externalRootWrapper, rootKeyId, withOrderByVersion(descendingOrderBy))
	if err != nil {
		return nil, "", fmt.Errorf("%s: error looking up root key versions for scope %q: %w", op, scopeId, err)
	}
	if len(rootKeyVersions) == 0 {
		return nil, "", fmt.Errorf("%s: no root key versions found for scope %q: %w", op, scopeId, ErrKeyNotFound)
	}

	var pooled *multi.PooledWrapper
	for i, key := range rootKeyVersions {
		var err error
		wrapper := aead.NewWrapper()
		if _, err = wrapper.SetConfig(ctx, wrapping.WithKeyId(key.GetPrivateId())); err != nil {
			return nil, "", fmt.Errorf("%s: error setting config on aead root wrapper in scope %q: %w", op, scopeId, err)
		}
		if err = wrapper.SetAesGcmKeyBytes(key.Key); err != nil {
			return nil, "", fmt.Errorf("%s: error setting key bytes on aead root wrapper in scope %q: %w", op, scopeId, err)
		}
		if i == 0 {
			pooled, err = multi.NewPooledWrapper(ctx, wrapper)
			if err != nil {
				return nil, "", fmt.Errorf("%s: error getting root pooled wrapper for key version 0 in scope %q: %w", op, scopeId, err)
			}
		} else {
			_, err = pooled.AddWrapper(ctx, wrapper)
			if err != nil {
				return nil, "", fmt.Errorf("%s: error adding pooled wrapper for key version %d in scope %q: %w", op, i, scopeId, err)
			}
		}
	}

	return pooled, rootKeyId, nil
}

func (k *Kms) loadDek(ctx context.Context, scopeId string, purpose KeyPurpose, rootWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) (*multi.PooledWrapper, error) {
	const op = "kms.loadDek"
	if scopeId == "" {
		return nil, fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	if rootWrapper == nil {
		return nil, fmt.Errorf("%s: nil root wrapper for scope %q: %w", op, scopeId, ErrInvalidParameter)
	}
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key ID for scope %q: %w", op, scopeId, ErrInvalidParameter)
	}
	if !purposeListContains(k.purposes, purpose) {
		return nil, fmt.Errorf("%s: not a supported key purpose %q: %w", op, purpose, ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	repo := opts.withRepository
	if repo == nil {
		repo = k.repo
	}
	keys, err := repo.ListDataKeys(ctx, withPurpose(purpose))
	if err != nil {
		return nil, fmt.Errorf("%s: error listing keys for purpose %q: %w", op, purpose, err)
	}
	var keyId string
	for _, k := range keys {
		if k.GetRootKeyId() == rootKeyId {
			keyId = k.GetPrivateId()
			break
		}
	}
	if keyId == "" {
		return nil, fmt.Errorf("%s: error finding %q key for scope %q: %w", op, purpose, scopeId, ErrKeyNotFound)
	}
	keyVersions, err := repo.ListDataKeyVersions(ctx, rootWrapper, keyId, withOrderByVersion(descendingOrderBy))
	if err != nil {
		return nil, fmt.Errorf("%s: error looking up %q key versions for scope %q: %w", op, purpose, scopeId, err)
	}
	if len(keyVersions) == 0 {
		return nil, fmt.Errorf("%s: no %q key versions found for scope %q: %w", op, purpose, scopeId, ErrKeyNotFound)
	}

	var pooled *multi.PooledWrapper
	for i, keyVersion := range keyVersions {
		var err error
		wrapper := aead.NewWrapper()
		if _, err = wrapper.SetConfig(ctx, wrapping.WithKeyId(keyVersion.GetPrivateId())); err != nil {
			return nil, fmt.Errorf("%s: error setting config on aead %q wrapper in scope %q: %w", op, purpose, scopeId, err)
		}
		if err = wrapper.SetAesGcmKeyBytes(keyVersion.GetKey()); err != nil {
			return nil, fmt.Errorf("%s: error setting key bytes on aead %q wrapper in scope %q: %w", op, purpose, scopeId, err)
		}
		if i == 0 {
			pooled, err = multi.NewPooledWrapper(ctx, wrapper)
			if err != nil {
				return nil, fmt.Errorf("%s: error getting %q pooled wrapper for key version 0 in scope %q: %w", op, purpose, scopeId, err)
			}
		} else {
			_, err = pooled.AddWrapper(ctx, wrapper)
			if err != nil {
				return nil, fmt.Errorf("%s: error getting %q pooled wrapper for key version %q in scope %q: %w", op, purpose, i, scopeId, err)
			}
		}
	}

	return pooled, nil
}

func isNil(i interface{}) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}

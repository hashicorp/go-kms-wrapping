package kms

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// LookupRootKeyVersion will look up a root key version in the repository. If
// the key version is not found then an ErrRecordNotFound will be returned.
func (r *repository) LookupRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, _ ...Option) (*rootKeyVersion, error) {
	const op = "kms.(repository).LookupRootKeyVersion"
	if privateId == "" {
		return nil, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	k := rootKeyVersion{}
	k.PrivateId = privateId
	if err := r.reader.LookupBy(ctx, &k); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: failed for %q: %w", op, privateId, ErrRecordNotFound)
		}
		return nil, fmt.Errorf("%s: failed for %q: %w", op, privateId, err)
	}
	if err := k.Decrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &k, nil
}

// CreateRootKeyVersion inserts into the repository and returns the new root key
// version with its PrivateId. Supported options: WithRetryCnt,
// WithRetryErrorsMatching
func (r *repository) CreateRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, key []byte, opt ...Option) (*rootKeyVersion, error) {
	const op = "kms.(repository).CreateRootKeyVersion"
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("%s: missing key: %w", op, ErrInvalidParameter)
	}
	kv := rootKeyVersion{}
	id, err := newRootKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	kv.PrivateId = id
	kv.RootKeyId = rootKeyId
	kv.Key = key
	if err := kv.Encrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	opts := getOpts(opt...)

	var returnedKey interface{}
	_, err = r.writer.DoTx(
		ctx,
		opts.withErrorsMatching,
		opts.withRetryCnt,
		dbw.ExpBackoff{},
		func(_ dbw.Reader, w dbw.Writer) error {
			returnedKey = kv.Clone()
			if err := create(ctx, w, returnedKey); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%s: failed for %q root key id: %w", op, kv.RootKeyId, err)
	}
	k, ok := returnedKey.(*rootKeyVersion)
	if !ok {
		return nil, fmt.Errorf("%s: not a RootKeyVersion: %w", op, ErrInternal)
	}
	return k, nil
}

// DeleteRootKeyVersion deletes the root key version for the provided id from the
// repository returning a count of the number of records deleted. Supported
// options: WithRetryCnt, WithRetryErrorsMatching
func (r *repository) DeleteRootKeyVersion(ctx context.Context, privateId string, opt ...Option) (int, error) {
	const op = "kms.(repository).DeleteRootKeyVersion"
	if privateId == "" {
		return noRowsAffected, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	k := rootKeyVersion{}
	k.PrivateId = privateId
	if err := r.reader.LookupBy(ctx, &k); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, privateId, ErrRecordNotFound)
		}
		return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, privateId, err)
	}

	opts := getOpts(opt...)

	var rowsDeleted int
	_, err := r.writer.DoTx(
		ctx,
		opts.withErrorsMatching,
		opts.withRetryCnt,
		dbw.ExpBackoff{},
		func(_ dbw.Reader, w dbw.Writer) (err error) {
			dk := k.Clone()
			// no oplog entries for root key version
			rowsDeleted, err = w.Delete(ctx, dk)
			if err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			if rowsDeleted > 1 {
				return fmt.Errorf("%s: more than 1 resource would have been deleted: %w", op, ErrMultipleRecords)
			}
			return nil
		},
	)
	if err != nil {
		return noRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, privateId, err)
	}
	return rowsDeleted, nil
}

// LatestRootKeyVersion searches for the root key version with the highest
// version number. When no results are found, it returns nil with an
// ErrRecordNotFound error.
func (r *repository) LatestRootKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, _ ...Option) (*rootKeyVersion, error) {
	const op = "kms.(repository).LatestRootKeyVersion"
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	var foundKeys []rootKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "root_key_id = ?", []interface{}{rootKeyId}, dbw.WithLimit(1), dbw.WithOrder("version desc")); err != nil {
		return nil, fmt.Errorf("%s: failed for %q: %w", op, rootKeyId, err)
	}
	if len(foundKeys) == 0 {
		return nil, fmt.Errorf("%s: %w", op, ErrRecordNotFound)
	}
	if err := foundKeys[0].Decrypt(ctx, keyWrapper); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &foundKeys[0], nil
}

// ListRootKeyVersions in versions of a root key. Supported options: WithLimit,
// WithOrderByVersion, WithReader
func (r *repository) ListRootKeyVersions(ctx context.Context, keyWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) ([]*rootKeyVersion, error) {
	const op = "kms.(repository).ListRootKeyVersions"
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	var versions []*rootKeyVersion
	err := r.list(ctx, &versions, "root_key_id = ?", []interface{}{rootKeyId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, keyWrapper); err != nil {
			return nil, fmt.Errorf("%s: error decrypting key num %d: %w", op, i, err)
		}
	}
	return versions, nil
}

// RewrapRootKeyVersions will rewrap (re-encrypt) the root key versions for a
// given rootKeyId with the latest wrapper. Supported options: WithReaderWriter
func (r *repository) RewrapRootKeyVersions(ctx context.Context, rootWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) error {
	const (
		op           = "kms.(repository).RewrapRootKeyVersions"
		keyFieldName = "CtKey"
	)
	if isNil(rootWrapper) {
		return fmt.Errorf("%s: missing root wrapper: %w", op, ErrInvalidParameter)
	}
	if rootKeyId == "" {
		return fmt.Errorf("%s: missing root key id: %w", op, ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	if opts.withWriter == nil {
		opts.withWriter = r.writer
	}
	if opts.withReader == nil {
		opts.withReader = r.reader
	}
	// rewrap the rootKey versions using the scope's root key to find them
	rkvs, err := r.ListRootKeyVersions(ctx, rootWrapper, rootKeyId, withReader(opts.withReader))
	if err != nil {
		return fmt.Errorf("%s: unable to list root key versions: %w", op, err)
	}
	for _, kv := range rkvs {
		if err := kv.Encrypt(ctx, rootWrapper); err != nil {
			return fmt.Errorf("%s: failed to rewrap root key version: %w", op, err)
		}
		rowsAffected, err := opts.withWriter.Update(ctx, kv, []string{keyFieldName}, nil, dbw.WithVersion(&kv.Version))
		if err != nil {
			return fmt.Errorf("%s: failed to update root key version: %w", op, err)
		}
		if rowsAffected != 1 {
			return fmt.Errorf("%s: expected to update 1 root key version and updated %d", op, rowsAffected)
		}
	}
	return nil
}

// RotateRootKeyVersion will rotate the key version for the given rootKeyId.
// Supported options: WithReaderWriter, withRandomReader
func (r *repository) RotateRootKeyVersion(ctx context.Context, rootWrapper wrapping.Wrapper, rootKeyId string, opt ...Option) (*rootKeyVersion, error) {
	const op = "kms.(repository).RotateRootKeyVersion"
	if isNil(rootWrapper) {
		return nil, fmt.Errorf("%s: missing root wrapper: %w", op, ErrInvalidParameter)
	}
	if rootKeyId == "" {
		return nil, fmt.Errorf("%s: missing root wrapper: %w", op, ErrInvalidParameter)
	}

	opts := getOpts(opt...)
	if opts.withWriter == nil {
		opts.withWriter = r.writer
	}
	if opts.withReader == nil {
		opts.withReader = r.reader
	}
	if isNil(opts.withRandomReader) {
		opts.withRandomReader = rand.Reader
	}

	rootKeyBytes, err := generateKey(ctx, opts.withRandomReader)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to generate key: %w", op, err)
	}
	rkv := rootKeyVersion{}
	id, err := newRootKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	rkv.PrivateId = id
	rkv.RootKeyId = rootKeyId
	rkv.Key = rootKeyBytes
	if err := rkv.Encrypt(ctx, rootWrapper); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if err := create(ctx, opts.withWriter, &rkv); err != nil {
		return nil, fmt.Errorf("%s: key versions: %w", op, err)
	}
	return &rkv, nil
}

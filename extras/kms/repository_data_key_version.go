package kms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// CreateDataKeyVersion inserts into the repository and returns the new key
// version with its PrivateId. Supported options: WithRetryCnt,
// WithRetryErrorsMatching
func (r *repository) CreateDataKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, dataKeyId string, key []byte, opt ...Option) (*dataKeyVersion, error) {
	const op = "kms.(repository).CreateDataKeyVersion"
	if rkvWrapper == nil {
		return nil, fmt.Errorf("%s: missing root key version wrapper: %w", op, ErrInvalidParameter)
	}
	if dataKeyId == "" {
		return nil, fmt.Errorf("%s: missing data key id: %w", op, ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("%s: missing key: %w", op, ErrInvalidParameter)
	}
	rootKeyVersionId, err := rkvWrapper.KeyId(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to get key id: %w", op, err)
	}
	switch {
	case rootKeyVersionId == "":
		return nil, fmt.Errorf("%s: missing root key version id: %w", op, ErrInvalidParameter)
	case !strings.HasPrefix(rootKeyVersionId, rootKeyVersionPrefix):
		return nil, fmt.Errorf("%s: root key version id %q doesn't start with prefix %q: %w", op, rootKeyVersionId, rootKeyVersionPrefix, ErrInvalidParameter)
	}
	kv := dataKeyVersion{}
	id, err := newDataKeyVersionId()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	kv.PrivateId = id
	kv.RootKeyVersionId = rootKeyVersionId
	kv.Key = key
	kv.DataKeyId = dataKeyId
	if err := kv.Encrypt(ctx, rkvWrapper); err != nil {
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
			// no oplog entries for root key version
			if err := create(ctx, w, returnedKey); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%s: failed for %q data key id: %w", op, kv.DataKeyId, err)
	}
	k, ok := returnedKey.(*dataKeyVersion)
	if !ok {
		return nil, fmt.Errorf("%s: not a DataKeyVersion: %w", op, ErrInternal)
	}
	return k, nil
}

// LookupDataKeyVersion will look up a key version in the repository. If
// the key version is not found then an ErrRecordNotFound will be returned.
func (r *repository) LookupDataKeyVersion(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, _ ...Option) (*dataKeyVersion, error) {
	const op = "kms.(repository).LookupDatabaseKeyVersion"
	if privateId == "" {
		return nil, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	k := dataKeyVersion{}
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

// DeleteDataKeyVersion deletes the key version for the provided id from the
// repository returning a count of the number of records deleted. Supported
// options: WithRetryCnt, WithRetryErrorsMatching
func (r *repository) DeleteDataKeyVersion(ctx context.Context, privateId string, opt ...Option) (int, error) {
	const op = "kms.(repository).DeleteDataKeyVersion"
	if privateId == "" {
		return noRowsAffected, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	k := dataKeyVersion{}
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
			// no oplog entries for the key version
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

// LatestDataKeyVersion searches for the key version with the highest
// version number. When no results are found, it returns nil with an
// ErrRecordNotFound error.
func (r *repository) LatestDataKeyVersion(ctx context.Context, rkvWrapper wrapping.Wrapper, dataKeyId string, _ ...Option) (*dataKeyVersion, error) {
	const op = "kms.(repository).LatestDataKeyVersion"
	if dataKeyId == "" {
		return nil, fmt.Errorf("%s: missing data key id: %w", op, ErrInvalidParameter)
	}
	if rkvWrapper == nil {
		return nil, fmt.Errorf("%s: missing root key version wrapper: %w", op, ErrInvalidParameter)
	}
	var foundKeys []*dataKeyVersion
	if err := r.reader.SearchWhere(ctx, &foundKeys, "data_key_id = ?", []interface{}{dataKeyId}, dbw.WithLimit(1), dbw.WithOrder("version desc")); err != nil {
		return nil, fmt.Errorf("%s: failed for %q: %w", op, dataKeyId, err)
	}
	if len(foundKeys) == 0 {
		return nil, fmt.Errorf("%s: %w", op, ErrRecordNotFound)
	}
	if err := foundKeys[0].Decrypt(ctx, rkvWrapper); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return foundKeys[0], nil
}

// ListDataKeyVersions will lists versions of a key. Supported options:
// WithLimit, WithOrderByVersion
func (r *repository) ListDataKeyVersions(ctx context.Context, rkvWrapper wrapping.Wrapper, databaseKeyId string, opt ...Option) ([]*dataKeyVersion, error) {
	const op = "kms.(repository).ListDataVersions"
	if databaseKeyId == "" {
		return nil, fmt.Errorf("%s: missing data key id: %w", op, ErrInvalidParameter)
	}
	if rkvWrapper == nil {
		return nil, fmt.Errorf("%s: missing root key version wrapper: %w", op, ErrInvalidParameter)
	}
	var versions []*dataKeyVersion
	err := r.list(ctx, &versions, "data_key_id = ?", []interface{}{databaseKeyId}, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	for i, k := range versions {
		if err := k.Decrypt(ctx, rkvWrapper); err != nil {
			return nil, fmt.Errorf("%s: error decrypting key num %q: %w", op, i, err)
		}
	}
	return versions, nil
}

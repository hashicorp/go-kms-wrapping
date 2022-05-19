package kms

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// CreateRootKey inserts into the repository and returns the new root key and
// root key version. Supported options: WithRetryCnt, WithRetryErrorsMatching
func (r *repository) CreateRootKey(ctx context.Context, keyWrapper wrapping.Wrapper, scopeId string, key []byte, opt ...Option) (*rootKey, *rootKeyVersion, error) {
	const op = "kms.(repository).CreateRootKey"
	opts := getOpts(opt...)
	var returnedRk *rootKey
	var returnedKv *rootKeyVersion
	_, err := r.writer.DoTx(
		ctx,
		opts.withErrorsMatching,
		opts.withRetryCnt,
		dbw.ExpBackoff{},
		func(_ dbw.Reader, w dbw.Writer) error {
			var err error
			if returnedRk, returnedKv, err = createRootKeyTx(ctx, w, keyWrapper, scopeId, key); err != nil {
				return fmt.Errorf("%s: %w", op, err)
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: failed for %q: %w", op, scopeId, err)
	}
	return returnedRk, returnedKv, nil
}

// createRootKeyTx inserts into the db (via dbw.Writer) and returns the new root key
// and root key version. This function encapsulates all the work required within
// a dbw.TxHandler
func createRootKeyTx(ctx context.Context, w dbw.Writer, keyWrapper wrapping.Wrapper, scopeId string, key []byte) (*rootKey, *rootKeyVersion, error) {
	const op = "kms.createRootKeyTx"
	if scopeId == "" {
		return nil, nil, fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	if len(key) == 0 {
		return nil, nil, fmt.Errorf("%s: missing key: %w", op, ErrInvalidParameter)
	}
	rk := rootKey{}
	kv := rootKeyVersion{}
	id, err := newRootKeyId()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", op, err)
	}
	rk.PrivateId = id
	rk.ScopeId = scopeId

	id, err = newRootKeyVersionId()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", op, err)
	}
	kv.PrivateId = id
	kv.RootKeyId = rk.PrivateId
	kv.Key = key
	if err := kv.Encrypt(ctx, keyWrapper); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := create(ctx, w, &rk); err != nil {
		return nil, nil, fmt.Errorf("%s: root keys: %w", op, err)
	}
	if err := create(ctx, w, &kv); err != nil {
		return nil, nil, fmt.Errorf("%s: key versions: %w", op, err)
	}

	return &rk, &kv, nil
}

// LookupRootKey will look up a root key in the repository. If the key is not
// found then an ErrRecordNotFound will be returned.
func (r *repository) LookupRootKey(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, _ ...Option) (*rootKey, error) {
	const op = "kms.(Repository).LookupRootKey"
	if privateId == "" {
		return nil, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	k := rootKey{}
	k.PrivateId = privateId
	if err := r.reader.LookupBy(ctx, &k); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: failed for %q: %w", op, privateId, ErrRecordNotFound)
		}
		return nil, fmt.Errorf("%s: failed for %q: %w", op, privateId, err)
	}
	return &k, nil
}

// DeleteRootKey deletes the root key for the provided id from the
// repository returning a count of the number of records deleted. Supported
// options: WithRetryCnt, WithRetryErrorsMatching
func (r *repository) DeleteRootKey(ctx context.Context, privateId string, opt ...Option) (int, error) {
	const op = "kms.(repository).DeleteRootKey"
	if privateId == "" {
		return noRowsAffected, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	k := rootKey{}
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
			// no oplog entries for root keys
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

// ListRootKeys will list the root keys. Supported options: WithLimit,
// WithOrderByVersion, WithReader
func (r *repository) ListRootKeys(ctx context.Context, opt ...Option) ([]*rootKey, error) {
	const op = "kms.(repository).ListRootKeys"
	var keys []*rootKey
	err := r.list(ctx, &keys, "1=1", nil, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return keys, nil
}

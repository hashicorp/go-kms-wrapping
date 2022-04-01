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
func (r *Repository) CreateRootKey(ctx context.Context, keyWrapper wrapping.Wrapper, scopeId string, key []byte, opt ...Option) (*RootKey, *RootKeyVersion, error) {
	const op = "kms.(Repository).CreateRootKey"
	opts := getOpts(opt...)
	var returnedRk *RootKey
	var returnedKv *RootKeyVersion
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
func createRootKeyTx(ctx context.Context, w dbw.Writer, keyWrapper wrapping.Wrapper, scopeId string, key []byte) (*RootKey, *RootKeyVersion, error) {
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
	rk := RootKey{}
	kv := RootKeyVersion{}
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
func (r *Repository) LookupRootKey(ctx context.Context, keyWrapper wrapping.Wrapper, privateId string, _ ...Option) (*RootKey, error) {
	const op = "kms.(Repository).LookupRootKey"
	if privateId == "" {
		return nil, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	if keyWrapper == nil {
		return nil, fmt.Errorf("%s: missing key wrapper: %w", op, ErrInvalidParameter)
	}
	k := RootKey{}
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
func (r *Repository) DeleteRootKey(ctx context.Context, privateId string, opt ...Option) (int, error) {
	const op = "kms.(Repository).DeleteRootKey"
	if privateId == "" {
		return NoRowsAffected, fmt.Errorf("%s: missing private id: %w", op, ErrInvalidParameter)
	}
	k := RootKey{}
	k.PrivateId = privateId
	if err := r.reader.LookupBy(ctx, &k); err != nil {
		if errors.Is(err, dbw.ErrRecordNotFound) {
			return NoRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, privateId, ErrRecordNotFound)
		}
		return NoRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, privateId, err)
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
		return NoRowsAffected, fmt.Errorf("%s: failed for %q: %w", op, privateId, err)
	}
	return rowsDeleted, nil
}

// ListRootKeys will list the root keys. Supported options: WithLimit,
// WithOrderByVersion
func (r *Repository) ListRootKeys(ctx context.Context, opt ...Option) ([]*RootKey, error) {
	const op = "kms.(Repository).ListRootKeys"
	var keys []*RootKey
	err := r.list(ctx, &keys, "1=1", nil, opt...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return keys, nil
}

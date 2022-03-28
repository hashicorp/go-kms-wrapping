package kms

import (
	"context"
	"fmt"
	"io"

	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/go-uuid"
)

const (
	// DefaultLimit is the default for results
	DefaultLimit = 10000

	DefaultWrapperSecret = "secret"

	// StdRetryCnt defines a standard retry count for transactions.
	StdRetryCnt = 20

	// NoRowsAffected defines the returned value for no rows affected
	NoRowsAffected = 0
)

// OrderBy defines an enum type for declaring a column's order by criteria.
type OrderBy int

const (
	// UnknownOrderBy would designate an unknown ordering of the column, which
	// is the standard ordering for any select without an order by clause.
	UnknownOrderBy = iota

	// AscendingOrderBy would designate ordering the column in ascending order.
	AscendingOrderBy

	// DescendingOrderBy would designate ordering the column in decending order.
	DescendingOrderBy
)

// Repository is the iam database repository
type Repository struct {
	reader dbw.Reader
	writer dbw.Writer
	// defaultLimit provides a default for limiting the number of results returned from the repo
	defaultLimit int
}

// NewRepository creates a new kms Repository. Supports the options: WithLimit
// which sets a default limit on results returned by repo operations.
func NewRepository(r dbw.Reader, w dbw.Writer, opt ...Option) (*Repository, error) {
	const op = "kms.NewRepository"
	if r == nil {
		return nil, fmt.Errorf("%s: nil reader: %w", op, ErrInvalidParameter)
	}
	if w == nil {
		return nil, fmt.Errorf("%s: nil writer: %w", op, ErrInvalidParameter)
	}
	if _, err := validateSchema(context.Background(), r); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	opts := getOpts(opt...)
	if opts.withLimit == 0 {
		// zero signals the boundary defaults should be used.
		opts.withLimit = DefaultLimit
	}
	return &Repository{
		reader:       r,
		writer:       w,
		defaultLimit: opts.withLimit,
	}, nil
}

// ValidateSchema will validate the database schema against the module's
// required migrations.Version
func (r *Repository) ValidateSchema(ctx context.Context) (string, error) {
	const op = "kms.(Repository).validateVersion"
	return validateSchema(ctx, r.reader)
}

func validateSchema(ctx context.Context, r dbw.Reader) (string, error) {
	const op = "kms.validateSchema"
	var s Schema
	if err := r.LookupWhere(ctx, &s, "1=1", nil); err != nil {
		return "", fmt.Errorf("%s: unable to get version: %w", op, err)
	}
	if s.Version != migrations.Version {
		return s.Version, fmt.Errorf("%s: invalid schema version, expected version %q and got %q: %w", op, migrations.Version, s.Version, ErrInvalidVersion)
	}
	return s.Version, nil
}

// DefaultLimit returns the default limit for listing as set on the repo
func (r *Repository) DefaultLimit() int {
	return r.defaultLimit
}

// list will return a listing of resources and honor the WithLimit option or the
// repo defaultLimit.  WithOrderByVersion is supported for types that have a
// version column
func (r *Repository) list(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error {
	opts := getOpts(opt...)
	limit := r.defaultLimit
	var dbOpts []dbw.Option
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	dbOpts = append(dbOpts, dbw.WithLimit(limit))
	switch resources.(type) {
	case *[]*RootKeyVersion, *[]*DataKeyVersion, []*RootKeyVersion, []*DataKeyVersion:
		switch opts.withOrderByVersion {
		case AscendingOrderBy:
			dbOpts = append(dbOpts, dbw.WithOrder("version asc"))
		case DescendingOrderBy:
			dbOpts = append(dbOpts, dbw.WithOrder("version desc"))
		}
	}
	return r.reader.SearchWhere(ctx, resources, where, args, dbOpts...)
}

type vetForWriter interface {
	vetForWrite(ctx context.Context, opType dbw.OpType) error
}

func create(ctx context.Context, writer dbw.Writer, i interface{}, opt ...dbw.Option) error {
	const op = "kms.(Repository).create"
	before := func(interface{}) error { return nil }
	if vetter, ok := i.(vetForWriter); ok {
		before = func(i interface{}) error {
			if err := vetter.vetForWrite(ctx, dbw.CreateOp); err != nil {
				return err
			}
			return nil
		}
	}
	if before != nil {
		opt = append(opt, dbw.WithBeforeWrite(before))
	}
	opt = append(opt, dbw.WithLookup(true))
	if err := writer.Create(ctx, i, opt...); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// KeyIder defines a common interface for all keys contained within a
// KeyWithVersion
type KeyIder interface {
	GetPrivateId() string
}

// KeyWithVersion encapsulates a key with its key version
type KeyWithVersion struct {
	Key        KeyIder
	KeyVersion KeyIder
}

// Keys defines a return type for CreateKeysTx so the returned keys can be
// easily accessed via their KeyPurpose
type Keys map[KeyPurpose]KeyWithVersion

// CreateKeysTx creates the root key and DEKs returns a map of the new keys.
// This function encapsulates all the work required within a dbw.TxHandler and
// allows this capability to be shared with other repositories or just called
// within a transaction.  To be clear, this repository function doesn't include
// it's own transaction and is intended to be used within a transaction provide
// by the caller.
func (r *Repository) CreateKeysTx(ctx context.Context, rootWrapper wrapping.Wrapper, randomReader io.Reader, scopeId string, purpose ...KeyPurpose) (Keys, error) {
	const op = "kms.CreateKeysTx"
	if rootWrapper == nil {
		return nil, fmt.Errorf("%s: missing root wrapper: %w", op, ErrInvalidParameter)
	}
	if randomReader == nil {
		return nil, fmt.Errorf("%s: missing random reader: %w", op, ErrInvalidParameter)
	}
	if scopeId == "" {
		return nil, fmt.Errorf("%s: missing scope id: %w", op, ErrInvalidParameter)
	}
	reserved := reservedKeyPurpose()
	dups := map[KeyPurpose]struct{}{}
	for _, p := range purpose {
		if strutil.StrListContains(reserved, string(p)) {
			return nil, fmt.Errorf("%s: reserved key purpose %q: %w", op, p, ErrInvalidParameter)
		}
		if _, ok := dups[p]; ok {
			return nil, fmt.Errorf("%s: duplicate key purpose %q: %w", op, p, ErrInvalidParameter)
		}
		dups[p] = struct{}{}
	}
	k, err := generateKey(ctx, randomReader)
	if err != nil {
		return nil, fmt.Errorf("%s: error generating random bytes for root key in scope %q: %w", op, scopeId, err)
	}
	rootKey, rootKeyVersion, err := createRootKeyTx(ctx, r.writer, rootWrapper, scopeId, k)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create root key in scope %q: %w", op, scopeId, err)
	}
	keys := Keys{
		KeyPurposeRootKey: KeyWithVersion{
			rootKey,
			rootKeyVersion,
		},
	}

	rkvWrapper := aead.NewWrapper()
	if _, err := rkvWrapper.SetConfig(ctx, wrapping.WithKeyId(rootKeyVersion.PrivateId)); err != nil {
		return nil, fmt.Errorf("%s: error setting config on aead root wrapper in scope %q: %w", op, scopeId, err)
	}
	if err := rkvWrapper.SetAesGcmKeyBytes(rootKeyVersion.Key); err != nil {
		return nil, fmt.Errorf("%s: error setting key bytes on aead root wrapper in scope %q: %w", op, scopeId, err)
	}

	for _, p := range purpose {
		k, err = generateKey(ctx, randomReader)
		if err != nil {
			return nil, fmt.Errorf("%s: error generating random bytes for data key of purpose %q in scope %q: %w", op, p, scopeId, err)
		}
		dataKey, dataKeyVersion, err := createDataKeyTx(ctx, r.reader, r.writer, rkvWrapper, p, k)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to create data key of purpose %q in scope %q: %w", op, p, scopeId, err)
		}
		keys[p] = KeyWithVersion{
			Key:        dataKey,
			KeyVersion: dataKeyVersion,
		}
	}
	return keys, nil
}

func generateKey(ctx context.Context, randomReader io.Reader) ([]byte, error) {
	const op = "kms.generateKey"
	k, err := uuid.GenerateRandomBytesWithReader(32, randomReader)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return k, nil
}

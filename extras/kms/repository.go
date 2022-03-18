package kms

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2/migrations"
)

// DefaultLimit is the default for results
const DefaultLimit = 10000

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
	var s Schema
	if err := r.reader.LookupWhere(ctx, &s, "1 = 1", nil); err != nil {
		return "", fmt.Errorf("%s: unable to get version: %w", op, err)
	}
	if s.Version != migrations.Version {
		return s.Version, fmt.Errorf("%s: expected version %q and got %q: %w", op, migrations.Version, s.Version, ErrInvalidVersion)
	}
	return s.Version, nil
}

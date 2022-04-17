package kms

import (
	"io"

	"github.com/hashicorp/go-dbw"
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withLimit          int
	withKeyId          string
	withOrderByVersion orderBy
	withRetryCnt       uint
	withErrorsMatching func(error) bool
	withPurpose        KeyPurpose
	withTx             *dbw.RW
	withRandomReader   io.Reader
	withReader         dbw.Reader
	withWriter         dbw.Writer
	withCache          bool
	withScopeIds       []string
}

var noOpErrorMatchingFn = func(error) bool { return false }

func getDefaultOptions() options {
	return options{
		withErrorsMatching: noOpErrorMatchingFn,
		withRetryCnt:       stdRetryCnt,
	}
}

// withLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If withLimit < 0, then unlimited results are returned. If
// withLimit == 0, then default limits are used for results.
func withLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithKeyId allows specifying a key ID that should be found in a scope's
// multiwrapper; if it is not found, keys will be refreshed
func WithKeyId(keyId string) Option {
	return func(o *options) {
		o.withKeyId = keyId
	}
}

// withOrderByVersion provides an option to specify ordering by the
// CreateTime field.
func withOrderByVersion(by orderBy) Option {
	return func(o *options) {
		o.withOrderByVersion = by
	}
}

// withRetryCount provides an optional specified retry count, otherwise the
// StdRetryCnt is used. You must specify WithRetryErrorsMatching if you want
// any retries at all.
func withRetryCount(cnt uint) Option {
	return func(o *options) {
		o.withRetryCnt = cnt
	}
}

// withRetryErrorsMatching provides an optional function to match transactions
// errors which should be retried.
func withRetryErrorsMatching(matchingFn func(error) bool) Option {
	return func(o *options) {
		o.withErrorsMatching = matchingFn
	}
}

// withPurpose provides an optional key purpose
func withPurpose(purpose KeyPurpose) Option {
	return func(o *options) {
		o.withPurpose = purpose
	}
}

// WithTx allows the caller to pass an inflight transaction to be used for all
// database operations. If WithTx(...) is used, then the caller is responsible
// for managing the transaction. The purpose of the WithTx(...) option is to
// allow the caller to create the scope and all of its keys in the same
// transaction.
func WithTx(tx *dbw.RW) Option {
	return func(o *options) {
		o.withTx = tx
	}
}

// WithRandomReadear(...) option allows an optional random reader to be
// provided.  By default the reader from crypto/rand will be used.
func WithRandomReader(randomReader io.Reader) Option {
	return func(o *options) {
		o.withRandomReader = randomReader
	}
}

// WithReaderWriter allows the caller to pass an inflight transaction to be used
// for all database operations. If WithReaderWriter(...) is used, then the
// caller is responsible for managing the transaction. The purpose of the
// WithReaderWriter(...) option is to allow the caller to create the scope and
// all of its keys in the same transaction.
func WithReaderWriter(r dbw.Reader, w dbw.Writer) Option {
	return func(o *options) {
		o.withReader = r
		o.withWriter = w
	}
}

// WithCache will enable the optional kms cache
func WithCache(enable bool) Option {
	return func(o *options) {
		o.withCache = enable
	}
}

// WithScopeIds allows an optional set of scope ids to be specified
func WithScopeIds(id ...string) Option {
	return func(o *options) {
		o.withScopeIds = id
	}
}
